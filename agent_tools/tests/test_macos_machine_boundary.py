"""Mac host source/package readback and exact native-provider interface tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import macos_machine_acceptance as gate
from agent_tools import macos_machine_boundary as subject


SOURCE = "a" * 40
REQUEST = {"correlationId": "11111111-1111-4111-8111-111111111111",
           "scenario": "install", "sourceSha": SOURCE, "sourceFingerprint": "b" * 64,
           "baseJarSha256": "c" * 64, "targetJarSha256": "d" * 64,
           "fixtureReceiptArtifactId": "sha256-" + "e" * 64}


class Provider:
    def __init__(self):
        self.calls = []
        self.observation = None

    def observe_admission(self, vm_name, source_sha, pair=None):
        self.calls.append(("observe", vm_name, source_sha, pair))
        return self.observation or {"vmName": vm_name, "sourceSha": source_sha}

    def submit_public(self, vm_name, campaign):
        self.calls.append(("submit", vm_name, campaign))
        return {"accepted": True}

    def observe_prompt(self, vm_name, job_id, operation_id):
        self.calls.append(("prompt", vm_name, job_id, operation_id))
        return {}

    def authorize_visible_prompt(self, vm_name, job_id, operation_id):
        self.calls.append(("authorize", vm_name, job_id, operation_id))

    def observe_terminal(self, vm_name, query):
        self.calls.append(("terminal", vm_name, query))
        return {}


def fixture(root):
    fixed = root / ".runtime/parity-evidence/continuation-macos" / ("fixture-" + SOURCE[:7])
    pair = fixed / "pair"
    pair.mkdir(parents=True)
    receipt = b'{"sourceSha":"' + SOURCE.encode() + b'"}'
    (pair / "fixture-receipt.json").write_bytes(receipt)
    request = {**REQUEST, "fixtureReceiptArtifactId": "sha256-" + hashlib.sha256(receipt).hexdigest()}
    records = {}
    for label, version in (("base", "2.1.19"), ("target", "2.2.0")):
        content = (label + " frozen DMG").encode()
        path = pair / "packages" / label / f"vpn-control-{version}.dmg"
        path.parent.mkdir(parents=True)
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        request[label + "DmgArtifactId"] = "sha256-" + digest
        records[label] = {"version": version, "artifactId": "sha256-" + digest,
                          "localPath": str(path), "size": len(content),
                          "mainJarSha256": request[label + "JarSha256"],
                          "codesignDeepStrict": "pass"}
    summary = {"sourceSha": SOURCE, "sourceFingerprint": REQUEST["sourceFingerprint"],
               "testOnly": True, "productionTrustChanged": False, "architecture": "arm64",
               "workflowConclusion": "success", "fixtureReceiptSha256": hashlib.sha256(receipt).hexdigest(),
               "packages": records}
    (fixed / "reviewed-package-summary.json").write_text(json.dumps(summary))
    return request, fixed


class MacMachineBoundaryTest(unittest.TestCase):
    def test_submit_rechecks_exact_pair_and_passes_immutable_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            request, _ = fixture(root)
            provider = Provider()
            provider.observation = {"sourceSha": SOURCE, "sourceFingerprint": request["sourceFingerprint"],
                "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
                "baseDmgArtifactId": request["baseDmgArtifactId"],
                "targetDmgArtifactId": request["targetDmgArtifactId"], **gate._fixed_paths(request),
                "vmRunning": True, "resourceAdmitted": True, "ownerReady": True,
                "runtimeRunning": False, "existingPromptCount": 0, "conflictingJobCount": 0,
                "legacyUnknownPreserved": True, "reservationId": "reservation", "bootSessionUuid": "boot",
                "controllerId": "controller", "ownerPid": 123, "ownerStartTicks": 456,
                "baseDevice": 1, "baseInode": 2, "baseJarSha256": request["baseJarSha256"],
                "baseSignatureValid": True, "baseRootOwned": True,
                "baseDmgSha256": request["baseDmgArtifactId"][7:],
                "targetDmgSha256": request["targetDmgArtifactId"][7:]}
            admitted = gate._admit(request, provider.observation)
            boundary = subject.MacMachineBoundary(root, provider)
            with patch.object(boundary, "current_source_sha", return_value=SOURCE), \
                 patch.object(boundary, "source_tree_clean", return_value=True):
                provider.observation["targetDmgArtifactId"] = "sha256-" + "f" * 64
                with self.assertRaises(gate.MacMachineAcceptanceError):
                    boundary.submit(request, admitted)
                self.assertFalse(any(call[0] == "submit" for call in provider.calls))
                provider.observation["targetDmgArtifactId"] = request["targetDmgArtifactId"]
                self.assertEqual(boundary.submit(request, admitted), {"accepted": True})
            submitted = [call for call in provider.calls if call[0] == "submit"]
            self.assertEqual(len(submitted), 1)
            self.assertIsInstance(submitted[0][2], subject.NativeCampaign)
            self.assertEqual(submitted[0][2].target_dmg_artifact_id, request["targetDmgArtifactId"])
            self.assertEqual(submitted[0][2].correlation_id, request["correlationId"])

    def test_exact_fixture_bytes_admit_and_changed_dmg_rejects_before_guest_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            request, fixed = fixture(root)
            provider = Provider()
            boundary = subject.MacMachineBoundary(root, provider)
            self.assertEqual(boundary.admission(request), {"vmName": gate.VM_NAME, "sourceSha": SOURCE})
            self.assertEqual(len(provider.calls), 1)
            target = fixed / "pair/packages/target/vpn-control-2.2.0.dmg"
            target.write_bytes(b"changed target")
            with self.assertRaisesRegex(subject.MacMachineBoundaryError, "size changed|bytes changed"):
                boundary.admission(request)
            self.assertEqual(len(provider.calls), 1)

    def test_source_probe_requires_exact_head_and_clean_status(self):
        with tempfile.TemporaryDirectory() as directory:
            boundary = subject.MacMachineBoundary(Path(directory), Provider())
            with patch.object(subject, "_run_git", side_effect=[SOURCE, ""]):
                self.assertEqual(boundary.current_source_sha(), SOURCE)
                self.assertTrue(boundary.source_tree_clean())
            with patch.object(subject, "_run_git", return_value=" M source.kt"):
                self.assertFalse(boundary.source_tree_clean())

    def test_secure_ui_provider_receives_only_exact_job_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = Provider()
            boundary = subject.MacMachineBoundary(Path(directory), provider)
            operation = {"jobId": "job-1", "operationId": "operation-1"}
            boundary.secure_authorize(REQUEST, operation)
            boundary.prompt(REQUEST, operation)
            admission = {**gate._fixed_paths(REQUEST), "ownerPid": 123, "ownerStartTicks": 456,
                         "bootSessionUuid": "boot", "reservationId": "reservation",
                         "controllerId": "controller"}
            boundary.terminal(REQUEST, {**operation, "admission": admission})
            self.assertEqual(provider.calls, [
                ("authorize", gate.VM_NAME, "job-1", "operation-1"),
                ("prompt", gate.VM_NAME, "job-1", "operation-1"),
                ("terminal", gate.VM_NAME, subject.NativeTerminalQuery(
                    SOURCE, "install", "operation-1", "job-1", admission["app"],
                    admission["guestRoot"], 123, 456, "boot", "reservation", "controller",
                    REQUEST["correlationId"], REQUEST["fixtureReceiptArtifactId"],
                    REQUEST["baseJarSha256"], REQUEST["targetJarSha256"]))])
            self.assertNotIn("password", repr(provider.calls).lower())

    def test_symlinked_fixture_ancestor_rejects_before_guest_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            request, fixed = fixture(root)
            linked = root / "linked"
            fixed.rename(linked)
            fixed.symlink_to(linked, target_is_directory=True)
            provider = Provider()
            boundary = subject.MacMachineBoundary(root, provider)
            with self.assertRaisesRegex(subject.MacMachineBoundaryError, "ancestor is unsafe"):
                boundary.admission(request)
            self.assertEqual(provider.calls, [])

    def test_summary_swap_during_pair_verification_rejects_before_guest_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            request, fixed = fixture(root)
            summary = fixed / "reviewed-package-summary.json"
            original = subject._sha256
            def mutate_after_target(path, size):
                result = original(path, size)
                if "packages/target/" in str(path):
                    summary.write_text(summary.read_text().replace('"success"', '"failure"'))
                return result
            provider = Provider()
            with patch.object(subject, "_sha256", side_effect=mutate_after_target):
                with self.assertRaisesRegex(subject.MacMachineBoundaryError, "summary changed"):
                    subject.MacMachineBoundary(root, provider).admission(request)
            self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()

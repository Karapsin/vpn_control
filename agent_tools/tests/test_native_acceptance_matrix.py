import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from agent_tools import native_acceptance_matrix as matrix
from agent_tools import native_artifact_registry as registry


class NativeAcceptanceMatrixTest(unittest.TestCase):
    SHA = "a" * 40
    REQUIREMENT = "android-api29-native-cli"
    SCENARIOS = ["api29-nondebuggable-build", "authorized-adb-cli", "unauthorized-caller", "consent-denial", "consent-grant", "on-off-runtime", "process-lifecycle", "documents-positive", "documents-negative"]

    def artifact(self, root, source=SHA, platform="android", name="artifact"):
        path = root / name; path.write_bytes((name + source).encode())
        return registry.register_artifact(root, {"platform": platform, "artifactKind": "package", "localPath": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size, "evidenceClass": "local-verified", "sourceSha": source})["artifactId"]

    def observation(self, root, artifact, scenarios=None, source=SHA, result="passed", scope="full-native", suffix="one", **changes):
        evidence = root / "evidence" / (suffix + ".json"); evidence.parent.mkdir(exist_ok=True); evidence.write_bytes(("evidence-" + suffix).encode())
        value = {"requirementId": self.REQUIREMENT, "platform": "android", "originalSourceSHA": source, "immutableArtifactIDs": [artifact], "evidencePath": str(evidence.relative_to(root)), "evidenceHash": hashlib.sha256(evidence.read_bytes()).hexdigest(), "environment": "pixel6-api29", "result": result, "scenarioResults": scenarios if scenarios is not None else {scenario: "passed" for scenario in self.SCENARIOS}, "missingEvidence": [], "nextFixedCommand": "none", "reviewerAttestation": "reviewed-native-observation", "evidenceScope": scope}
        value.update(changes); return value

    def row(self, root, source=SHA):
        return next(row for row in matrix.matrix_status(root, source)["requirements"] if row["requirementId"] == self.REQUIREMENT)

    def test_status_with_no_receipt_store_is_open_and_does_not_create_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = matrix.matrix_status(root, self.SHA)
            self.assertEqual("open", status["gate"])
            self.assertFalse((root / ".rag_index").exists())

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_status_reads_published_receipts_without_creating_a_lockfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = self.artifact(root)
            matrix.matrix_record(root, self.observation(root, artifact))
            lock = root / ".rag_index" / "native-acceptance" / ".lock"
            lock.unlink()

            self.assertEqual("passed", self.row(root)["status"])
            self.assertFalse(lock.exists())

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_current_full_observation_covers_requirement_but_not_full_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = self.artifact(root); matrix.matrix_record(root, self.observation(root, artifact))
            self.assertEqual("passed", self.row(root)["status"]); self.assertEqual("open", matrix.matrix_status(root, self.SHA)["gate"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_actual_evidence_bytes_are_stream_hashed_and_changed_file_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = self.artifact(root); observation = self.observation(root, artifact)
            (root / observation["evidencePath"]).write_bytes(b"changed-after-hash")
            with self.assertRaisesRegex(matrix.NativeAcceptanceMatrixError, "hash does not match"): matrix.matrix_record(root, observation)
            observation = self.observation(root, artifact, suffix="recorded")
            matrix.matrix_record(root, observation)
            (root / observation["evidencePath"]).write_bytes(b"changed-after-recording")
            self.assertEqual("unknown", self.row(root)["status"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_forged_registration_flag_does_not_replace_actual_registry_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fake = "sha256-" + "b" * 64
            with self.assertRaises(matrix.NativeAcceptanceMatrixError): matrix.matrix_record(root, self.observation(root, fake, artifactRefRegistered=True))

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_two_current_partial_receipts_union_deterministically(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = self.artifact(root)
            matrix.matrix_record(root, self.observation(root, artifact, scenarios={s: "passed" for s in self.SCENARIOS[:4]}, suffix="first"))
            matrix.matrix_record(root, self.observation(root, artifact, scenarios={s: "passed" for s in self.SCENARIOS[4:]}, suffix="second"))
            self.assertEqual("passed", self.row(root)["status"]); self.assertEqual(2, self.row(root)["receiptCount"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_current_beats_historical_and_historical_remains_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); old = self.artifact(root, source="c" * 40, name="old"); current = self.artifact(root, name="current")
            matrix.matrix_record(root, self.observation(root, old, source="c" * 40, suffix="old")); matrix.matrix_record(root, self.observation(root, current, suffix="current"))
            self.assertEqual("passed", self.row(root)["status"]); self.assertEqual("historical", self.row(root, "d" * 40)["status"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_conflicting_and_unknown_observations_remain_unresolved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = self.artifact(root)
            matrix.matrix_record(root, self.observation(root, artifact, scenarios={"consent-grant": "passed"}, suffix="pass")); matrix.matrix_record(root, self.observation(root, artifact, scenarios={"consent-grant": "failed"}, result="failed", suffix="fail", nextFixedCommand="inspect-evidence"))
            self.assertEqual("conflicting", self.row(root)["status"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = self.artifact(root); matrix.matrix_record(root, self.observation(root, artifact, result="unknown", suffix="unknown", nextFixedCommand="inspect-evidence"))
            self.assertEqual("unknown", self.row(root)["status"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_component_scope_and_missing_scenarios_never_close_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = self.artifact(root); matrix.matrix_record(root, self.observation(root, artifact, scope="component"))
            row = self.row(root); self.assertEqual("open", row["status"]); self.assertEqual(self.SCENARIOS, row["missingScenarios"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX")
    def test_duplicate_and_unsafe_path_are_rejected_and_receipts_are_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = self.artifact(root); observation = self.observation(root, artifact); stored = matrix.matrix_record(root, observation)
            with self.assertRaisesRegex(matrix.NativeAcceptanceMatrixError, "duplicate"): matrix.matrix_record(root, observation)
            self.assertEqual(0o600, Path(stored["receiptPath"]).stat().st_mode & 0o777)
            with self.assertRaises(matrix.NativeAcceptanceMatrixError): matrix.matrix_record(root, self.observation(root, artifact, suffix="bad", evidencePath="../outside"))


if __name__ == "__main__": unittest.main()

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from agent_tools import native_acceptance_matrix as matrix
from agent_tools import native_acceptance_overview as overview
from agent_tools import native_artifact_registry as registry
from agent_tools import native_artifact_reuse as reuse


@unittest.skipIf(os.name == "nt", "private acceptance evidence requires POSIX ownership")
class NativeAcceptanceEquivalenceTest(unittest.TestCase):
    requirement = "android-api29-native-cli"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"; self.root.mkdir()
        self.git("init", "-q"); self.git("config", "user.email", "test@example.org"); self.git("config", "user.name", "Test")
        (self.root / ".gitignore").write_text(".rag_index/\n", encoding="utf-8")
        (self.root / "gradle.properties").write_text("vpnControlVersion=2.1.18\n", encoding="utf-8")
        (self.root / "src.kt").write_text("val x = 1\n", encoding="utf-8")
        (self.root / "runtime.bin").write_bytes(b"runtime-v1")
        (self.root / "docs").mkdir(); (self.root / "docs" / "guide.md").write_text("before\n", encoding="utf-8")
        (self.root / "evidence.json").write_bytes(b"native evidence")
        (self.root / "partial-evidence.json").write_bytes(b"partial native evidence")
        self.commit(); self.original = self.head()
        package = Path(self.temp.name) / "fixture.apk"; package.write_bytes(b"fixture-package")
        registered = registry.register_artifact(self.root, {"platform": "android", "artifactKind": "package", "localPath": str(package),
            "sha256": hashlib.sha256(package.read_bytes()).hexdigest(), "size": package.stat().st_size,
            "evidenceClass": "local-verified", "sourceSha": self.original})
        self.frozen = reuse.artifact_set_freeze(self.root, {"sourceSha": self.original,
            "packages": [{"artifactId": registered["artifactId"], "locationId": registered["locations"][0]["locationId"]}],
            "runtimePaths": ["runtime.bin"], "provenance": {"architecture": "x86_64", "signer": {"kind": "unsigned"}}})
        scenarios = matrix.load_requirements()[self.requirement]["requiredScenarios"]
        self.record = matrix.matrix_record(self.root, {"requirementId": self.requirement, "platform": "android",
            "originalSourceSHA": self.original, "immutableArtifactIDs": [registered["artifactId"]], "evidencePath": "evidence.json",
            "evidenceHash": hashlib.sha256(b"native evidence").hexdigest(), "environment": "fixture-api29", "result": "passed",
            "scenarioResults": {scenario: "passed" for scenario in scenarios}, "missingEvidence": [], "nextFixedCommand": "none",
            "reviewerAttestation": "reviewed full native fixture", "evidenceScope": "full-native"})

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.root, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

    def commit(self) -> None:
        self.git("add", "-A"); self.git("commit", "-qm", "fixture")

    def head(self) -> str:
        return self.git("rev-parse", "HEAD")

    def row(self, source: str) -> dict:
        return next(item for item in matrix.matrix_status(self.root, source)["requirements"] if item["requirementId"] == self.requirement)

    def test_actual_docs_only_reuse_is_historical_until_immutable_link_then_passes(self) -> None:
        (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        decision = reuse.artifact_reuse_check(self.root, {"artifactSetId": self.frozen["artifactSetId"]})
        self.assertEqual("verified-equivalent-product-inputs", decision["decision"])
        # This is the actual pre-fix failure: byte reuse was eligible, but the
        # native receipt was ignored solely because its source was original.
        self.assertEqual("historical", self.row(target)["status"])
        link = matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"],
            "artifactSetId": self.frozen["artifactSetId"], "targetSourceSHA": target,
            "reviewerAttestation": "reviewed docs-only equivalence"})
        row = self.row(target)
        self.assertEqual("passed", row["status"])
        self.assertEqual(self.original, row["originalSourceSHA"])
        self.assertEqual(target, row["equivalentToSourceSHA"])
        self.assertEqual(link["linkId"], row["equivalenceLinkId"])
        self.assertEqual(["exact-sha-ci"], row["requiredCurrentChecks"])
        readonly = overview.matrix_status_readonly(self.root, target, matrix, registry, {"records": {}, "matches": []})
        readonly_row = next(item for item in readonly["requirements"] if item["requirementId"] == self.requirement)
        self.assertEqual("passed", readonly_row["status"])
        self.assertEqual(link["linkId"], readonly_row["equivalenceLinkId"])
        link_path = self.root / ".rag_index" / "native-acceptance" / "equivalences" / (link["linkId"] + ".json")
        link_path.write_text("{}", encoding="utf-8")
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            self.row(target)

    def test_product_critical_diff_dirty_checkout_and_partial_receipt_reject_link(self) -> None:
        (self.root / "src.kt").write_text("val x = 2\n", encoding="utf-8"); self.commit()
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
                "targetSourceSHA": self.head(), "reviewerAttestation": "reviewed"})

    def test_symlink_mode_rename_critical_tool_and_partial_receipt_reject(self) -> None:
        for action in ("symlink", "mode", "rename", "critical-tool"):
            if action != "symlink":
                self.setUp()
            guide = self.root / "docs" / "guide.md"
            if action == "symlink":
                guide.unlink(); guide.symlink_to("../src.kt")
            elif action == "mode":
                guide.chmod(0o755)
            elif action == "rename":
                self.git("mv", "docs/guide.md", "docs/renamed.md")
            else:
                path = self.root / "agent_tools"; path.mkdir()
                (path / "native_acceptance_matrix.py").write_text("changed\n", encoding="utf-8")
            self.commit()
            with self.assertRaises(matrix.NativeAcceptanceMatrixError):
                matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
                    "targetSourceSHA": self.head(), "reviewerAttestation": "reviewed"})

        self.setUp(); (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit()
        scenarios = matrix.load_requirements()[self.requirement]["requiredScenarios"]
        partial = matrix.matrix_record(self.root, {"requirementId": self.requirement, "platform": "android", "originalSourceSHA": self.original,
            "immutableArtifactIDs": self.record and [self.frozen["packages"][0]["artifactId"]], "evidencePath": "partial-evidence.json",
            "evidenceHash": hashlib.sha256(b"partial native evidence").hexdigest(), "environment": "fixture-api29", "result": "passed",
            "scenarioResults": {scenarios[0]: "passed"}, "missingEvidence": [], "nextFixedCommand": "none",
            "reviewerAttestation": "partial evidence", "evidenceScope": "component"})
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            matrix.matrix_equivalence_record(self.root, {"receiptId": partial["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
                "targetSourceSHA": self.head(), "reviewerAttestation": "reviewed"})
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
                "targetSourceSHA": self.head(), "reviewerAttestation": "reviewed"})

    def test_committed_test_or_noncritical_tool_change_retains_current_check_obligations(self) -> None:
        (self.root / "tests").mkdir(exist_ok=True)
        (self.root / "tests" / "proof.py").write_text("assert True\n", encoding="utf-8")
        self.commit(); target = self.head()
        link = matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed test equivalence"})
        self.assertEqual(["exact-sha-ci", "changed-tool-tests"], link["requiredCurrentChecks"])
        self.setUp(); (self.root / "agent_tools").mkdir()
        (self.root / "agent_tools" / "observer.py").write_text("VALUE = 1\n", encoding="utf-8")
        self.commit(); target = self.head()
        link = matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed tool equivalence"})
        self.assertEqual(["exact-sha-ci", "changed-tool-tests"], link["requiredCurrentChecks"])

    def test_status_refuses_post_read_receipt_symlink_exchange(self) -> None:
        (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed docs equivalence"})
        receipt = (self.root / ".rag_index" / "native-acceptance" / (self.record["receiptId"] + ".json")).resolve()
        preserved = receipt.parent / "preserved-proof.private"; reads = []; original = matrix._read_receipt
        def exchange(path, *args, **kwargs):
            answer = original(path, *args, **kwargs)
            if Path(path).resolve() == receipt:
                reads.append(1)
                if len(reads) == 2:
                    receipt.rename(preserved); receipt.symlink_to(preserved)
            return answer
        with mock.patch.object(matrix, "_read_receipt", side_effect=exchange):
            self.assertEqual("historical", self.row(target)["status"])
        self.assertTrue(receipt.is_symlink())

    def test_status_refuses_post_read_receipt_metadata_mode_or_link_count_change(self) -> None:
        (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed docs equivalence"})
        receipt = self.root / ".rag_index" / "native-acceptance" / (self.record["receiptId"] + ".json")
        original = matrix._read_receipt; reads = []
        def metadata_change(path, *args, **kwargs):
            answer = original(path, *args, **kwargs)
            if Path(path).resolve() == receipt.resolve():
                reads.append(1)
                if len(reads) == 2:
                    now = receipt.stat(); os.utime(receipt, ns=(now.st_atime_ns, now.st_mtime_ns + 1_000_000_000))
            return answer
        with mock.patch.object(matrix, "_read_receipt", side_effect=metadata_change):
            self.assertEqual("historical", self.row(target)["status"])
        self.assertGreaterEqual(len(reads), 2)
        self.setUp(); (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed docs equivalence"})
        receipt = self.root / ".rag_index" / "native-acceptance" / (self.record["receiptId"] + ".json")
        receipt.chmod(0o644)
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            self.row(target)
        receipt.chmod(0o600); os.link(receipt, receipt.parent / "retained-proof-hardlink")
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            self.row(target)

    def test_boolean_schema_and_hardlinked_equivalence_are_rejected(self) -> None:
        (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        link = matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed docs equivalence"})
        path = self.root / ".rag_index" / "native-acceptance" / "equivalences" / (link["linkId"] + ".json")
        value = json.loads(path.read_bytes()); value["schemaVersion"] = True; value.pop("linkId")
        replacement = "native-equivalence-" + hashlib.sha256(matrix._encode(value)).hexdigest()[:32]
        path.unlink(); path = path.with_name(replacement + ".json"); path.write_bytes(matrix._encode({"linkId": replacement, **value})); path.chmod(0o600)
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            self.row(target)
        self.setUp(); (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        link = matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "different reviewed attestation"})
        path = self.root / ".rag_index" / "native-acceptance" / "equivalences" / (link["linkId"] + ".json")
        os.link(path, path.parent / "retained-hardlink")
        with self.assertRaises(matrix.NativeAcceptanceMatrixError):
            self.row(target)

    def test_status_refuses_checkout_or_dirty_change_during_equivalence_proof(self) -> None:
        (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed docs equivalence"})
        original_diff = reuse._equivalence_diff
        def checkout_after_diff(root, *args):
            answer = original_diff(root, *args)
            self.git("checkout", "-q", self.original)
            return answer
        with mock.patch.object(reuse, "_equivalence_diff", side_effect=checkout_after_diff):
            self.assertEqual("historical", self.row(target)["status"])
        self.git("checkout", "-q", target)
        def dirty_after_diff(root, *args):
            answer = original_diff(root, *args)
            (self.root / "docs" / "guide.md").write_text("dirty\n", encoding="utf-8")
            return answer
        with mock.patch.object(reuse, "_equivalence_diff", side_effect=dirty_after_diff):
            self.assertEqual("historical", self.row(target)["status"])

    def test_readonly_overview_preserves_registry_temporary_and_later_unknown_reopens_link(self) -> None:
        (self.root / "docs" / "guide.md").write_text("after\n", encoding="utf-8"); self.commit(); target = self.head()
        matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"], "artifactSetId": self.frozen["artifactSetId"],
            "targetSourceSHA": target, "reviewerAttestation": "reviewed docs equivalence"})
        temporary = self.root / registry.INDEX_RELATIVE / ".tmp-review-preserve"; temporary.write_text("unfinished", encoding="utf-8"); temporary.chmod(0o600)
        overview.matrix_status_readonly(self.root, target, matrix, registry, {"records": {}, "matches": []})
        self.assertTrue(temporary.exists())
        scenarios = matrix.load_requirements()[self.requirement]["requiredScenarios"]
        matrix.matrix_record(self.root, {"requirementId": self.requirement, "platform": "android", "originalSourceSHA": self.original,
            "immutableArtifactIDs": [self.frozen["packages"][0]["artifactId"]], "evidencePath": "partial-evidence.json",
            "evidenceHash": hashlib.sha256(b"partial native evidence").hexdigest(), "environment": "fixture-api29", "result": "unknown",
            "scenarioResults": {scenarios[0]: "unknown"}, "missingEvidence": [], "nextFixedCommand": "inspect-evidence",
            "reviewerAttestation": "later unknown", "evidenceScope": "component"})
        self.assertEqual("historical", self.row(target)["status"])


if __name__ == "__main__":
    unittest.main()

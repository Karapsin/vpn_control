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


class EquivalenceRepository:
    """A real Git repository with a frozen set, a registered package and a passed full-native record of its first commit."""
    requirement = "android-api29-native-cli"
    layout: dict[str, str] = {}

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"; self.root.mkdir()
        self.git("init", "-q"); self.git("config", "user.email", "test@example.org"); self.git("config", "user.name", "Test")
        for path, text in self.layout.items():
            (self.root / path).parent.mkdir(parents=True, exist_ok=True); (self.root / path).write_text(text, encoding="utf-8")
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


@unittest.skipIf(os.name == "nt", "private acceptance evidence requires POSIX ownership")
class NativeAcceptanceEquivalenceTest(EquivalenceRepository, unittest.TestCase):
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


# A repository shaped like this one: a Gradle product with a test source set and a test-only srcDir, a scenario bundle
# table, a host driver whose closure reaches the MCP server by a late import, the selector with its manifest, dispatch
# pins no module names, tests, fixtures and an unrelated tool whose name holds the tokens the old path rule refused.
LAYOUT = {
    "settings.gradle.kts": 'rootProject.name = "fixture"\ninclude(":desktopApp")\n',
    "desktopApp/build.gradle.kts": 'kotlin { sourceSets.getByName("desktopTest").resources.srcDir(rootProject.file("visual-tests")) }\n',
    "desktopApp/src/main/kotlin/Main.kt": "fun main() = Unit\n",
    "desktopApp/src/desktopTest/kotlin/MainTest.kt": "class MainTest\n",
    "visual-tests/scenes.json": "{}\n",
    "scripts/package_windows_desktop.ps1": "Write-Output package\n",
    "scripts/test_packaged_cli.py": "HARNESS = 1\n",
    "scripts/test_release_notes.py": "assert True\n",
    "agent_tools/native_scenario_bundle.py":
        '_SCENARIOS = {"windows-scenario-driver": ("agent_tools/windows_case_runner.py", "scripts/test_packaged_cli.py")}\n',
    "agent_tools/windows_case_runner.py": "CASES = 1\n",
    "agent_tools/native_scenario_windows.py": "from . import native_scenario_bundle, windows_scenario_host_job\n",
    "agent_tools/windows_scenario_host_job.py": "def late():\n    from . import mcp_server\n    return mcp_server\n",
    "agent_tools/mcp_server.py": 'SELECTOR = "affected_agent_test_dependencies.json"\nPOLICY = "tool_action_policy.json"\n',
    "agent_tools/tool_action_policy.json": "{}\n",
    "agent_tools/native_acceptance_matrix.py": 'LEDGER = "native_acceptance_requirements.json"\n',
    "agent_tools/native_acceptance_requirements.json": "{}\n",
    "agent_tools/affected_agent_tests.py": 'DEPENDENCY_MANIFEST = "affected_agent_test_dependencies.json"\nENV = "requirements-mcp.txt"\n',
    ".mcp.json": '{"mcpServers": {"fixture": {"command": "bash", "args": ["-c", "exec bash \\"$root/agent_tools/mcp_server.sh\\""]}}}\n',
    "agent_tools/mcp_server.sh": 'pip install -r "$root/agent_tools/requirements-mcp.txt"\nexec python "$root/agent_tools/mcp_server.py" serve\n',
    "agent_tools/requirements-mcp.txt": "mcp==1.0\n",
    "agent_tools/affected_agent_test_dependencies.json": "{}\n",
    "agent_tools/readiness_vm_dispatch.json": "{}\n",
    "agent_tools/native_package_release_report.py": "REPORT = 1\n",
    "agent_tools/tests/test_native_scenario_windows.py": "assert True\n",
    "agent_tools/tests/fixtures/windows_native_case/before.source": "before\n",
}


@unittest.skipIf(os.name == "nt", "private acceptance evidence requires POSIX ownership")
class ExecutedInputScopeTest(EquivalenceRepository, unittest.TestCase):
    """S3: a link ends only when a commit changes an input the recorded scenario executed."""
    layout = LAYOUT

    def link(self, path: str, text: str = "changed\n") -> dict:
        self.setUp()
        (self.root / path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / path).write_text(text, encoding="utf-8"); self.commit()
        link = matrix.matrix_equivalence_record(self.root, {"receiptId": self.record["receiptId"],
            "artifactSetId": self.frozen["artifactSetId"], "targetSourceSHA": self.head(), "reviewerAttestation": "reviewed " + path})
        stored = self.root / ".rag_index" / "native-acceptance" / "equivalences" / (link["linkId"] + ".json")
        return {**json.loads(stored.read_bytes()), **link}

    def test_test_fixture_selector_and_unrelated_tool_commits_keep_the_link(self) -> None:
        kept = {
            "agent_tools/tests/test_native_scenario_windows.py": "test",  # a test-only commit
            "agent_tools/tests/fixtures/windows_native_case/before.source": "fixture",  # a fixture-only commit
            "agent_tools/tests/fixtures/windows_native_case/after.source": "fixture",
            "agent_tools/affected_agent_test_dependencies.json": "metadata",  # selector metadata, though the MCP server names it
            "agent_tools/readiness_vm_dispatch.json": "agent-tool",  # dispatch pins no executed module names
            "agent_tools/native_package_release_report.py": "agent-tool",
            "desktopApp/src/desktopTest/kotlin/MainTest.kt": "test",
            "visual-tests/scenes.json": "test",
            "scripts/test_release_notes.py": "test",
            "agent_tools/README.md": "docs",
            "docs/guide.md": "docs",
        }
        for path, kind in kept.items():
            with self.subTest(path=path):
                link = self.link(path)
                self.assertEqual([kind], [entry["class"] for entry in link["changedPaths"]])
                self.assertEqual("passed", self.row(self.head())["status"])
                self.assertEqual(["exact-sha-ci"] + (["changed-tool-tests"] if kind != "docs" else []), link["requiredCurrentChecks"])

    def test_bundle_host_classifier_product_and_version_commits_end_the_link(self) -> None:
        ended = {
            "agent_tools/windows_case_runner.py": "CASES = 2\n",  # a bundle file shipped to the guest
            "scripts/test_packaged_cli.py": "HARNESS = 2\n",  # a bundle file outside agent_tools, named like a test
            "agent_tools/native_scenario_bundle.py":
                '_SCENARIOS = {"windows-scenario-driver": ("agent_tools/windows_case_runner.py",)}\n',  # the bundle table
            "agent_tools/native_scenario_windows.py": "from . import native_scenario_bundle\n",  # the host driver
            "agent_tools/windows_scenario_host_job.py": "VALUE = 2\n",  # its import closure
            "agent_tools/mcp_server.py": 'SELECTOR = "affected_agent_test_dependencies.json"\n',  # reached by a late import
            "agent_tools/tool_action_policy.json": '{"changed": true}\n',  # a resource the closure names
            "agent_tools/native_acceptance_requirements.json": '{"changed": true}\n',  # the classifier's ledger
            "agent_tools/requirements-mcp.txt": "mcp==2.0\n",  # the MCP route's environment, though the selector names it too
            "agent_tools/mcp_server.sh": "exec python agent_tools/mcp_server.py\n",  # the MCP route's launcher
            ".mcp.json": "{}\n",  # the MCP server registration
            "desktopApp/src/main/kotlin/Main.kt": "fun main() = println()\n",  # product code
            "scripts/package_windows_desktop.ps1": "Write-Output changed\n",  # a product build input
            "gradle.properties": "vpnControlVersion=2.1.19\n",  # a version roll
            "settings.gradle.kts": 'include(":desktopApp")\ninclude(":other")\n',
        }
        for path, text in ended.items():
            with self.subTest(path=path):
                with self.assertRaises(matrix.NativeAcceptanceMatrixError):
                    self.link(path, text)
                self.assertEqual("historical", self.row(self.head())["status"])

    def test_a_new_import_makes_an_unrelated_tool_an_executed_input(self) -> None:
        self.link("agent_tools/native_package_release_report.py")  # unrelated: kept
        self.setUp()
        # The host job now imports it: at the target it is in the closure, so the next change to it ends a link.
        (self.root / "agent_tools/windows_scenario_host_job.py").write_text(
            "from . import native_package_release_report\n", encoding="utf-8"); self.commit()
        changed = self.head()
        source = reuse._ScopedInputs(self.root, self.original, changed)
        self.assertEqual("host-tool", source.classify("agent_tools/native_package_release_report.py"))
        self.assertIn("agent_tools/native_package_release_report.py", source.executed_paths())


# The MCP route of review finding 2: the server loads adapters by name and executes sibling sources by with_name, and
# the dispatch adapter reads its catalog by with_suffix. None of them is a static import of the host closure.
BY_NAME_LAYOUT = {
    **LAYOUT,
    "agent_tools/mcp_server.py": 'SELECTOR = "affected_agent_test_dependencies.json"\nPOLICY = "tool_action_policy.json"\n'
                                 '_VM_NATIVE_ADAPTERS = ("readiness_vm_dispatch",)\n'
                                 'def _agent_module(name):\n    return name\n'
                                 'def route():\n    return _agent_module("ssh_program_execution")\n'
                                 'import importlib\n'
                                 'def lazy():\n    return importlib.import_module("agent_tools.windows_relay_helper")\n',
    "agent_tools/readiness_vm_dispatch.py": 'from pathlib import Path\nMANIFEST = Path(__file__).with_suffix(".json")\n'
                                            'GATEWAY = Path(__file__).with_name("gateway.source")\n',
    "agent_tools/gateway.source": "GATEWAY = 1\n",
    "agent_tools/ssh_program_execution.py": 'from pathlib import Path\nREMOTE = Path(__file__).with_name("ssh_program_execution_remote.py")\n',
    "agent_tools/ssh_program_execution_remote.py": "REMOTE = 1\n",
    "agent_tools/windows_relay_helper.py": "HELPER = 1\n",
}
BY_NAME_ENDED = {
    "agent_tools/readiness_vm_dispatch.py": 'from pathlib import Path\nMANIFEST = Path(__file__).with_suffix(".json")\n'
                                            'GATEWAY = Path(__file__).with_name("gateway.source")\nX = 2\n',
    "agent_tools/readiness_vm_dispatch.json": '{"changed": true}\n',
    "agent_tools/gateway.source": "GATEWAY = 2\n",
    "agent_tools/ssh_program_execution.py": 'from pathlib import Path\nREMOTE = Path(__file__).with_name("ssh_program_execution_remote.py")\nX = 2\n',
    "agent_tools/ssh_program_execution_remote.py": "REMOTE = 2\n",
    "agent_tools/windows_relay_helper.py": "HELPER = 2\n",
}


@unittest.skipIf(os.name == "nt", "private acceptance evidence requires POSIX ownership")
class StringLoadedInputScopeTest(EquivalenceRepository, unittest.TestCase):
    """Review finding 2: a commit to a string-loaded MCP adapter or its resources ends the link."""
    layout = BY_NAME_LAYOUT
    link = ExecutedInputScopeTest.link

    def before(self):
        fixture = Path(__file__).parent / "fixtures" / "native_artifact_reuse_by_name"
        source = fixture / "native_artifact_reuse.before.source"
        provenance = json.loads((fixture / "provenance.json").read_bytes())
        self.assertEqual(provenance["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        return source

    def test_each_string_loaded_adapter_or_resource_ends_the_link_RED_kept_GREEN(self):
        from agent_tools.tests import red_gate
        source = self.before()
        if red_gate.red_required(self, source):
            namespace = {"__name__": "agent_tools.native_artifact_reuse_before", "__package__": "agent_tools",
                         "__file__": str(source)}
            exec(compile(source.read_bytes(), str(source), "exec"), namespace)
            head = self.head()
            old = namespace["_ScopedInputs"](self.root, head, head)
            # RED: the bf8d2da2 scope treated every one of them as an unrelated tool, so its commit kept the link.
            self.assertEqual({path: "agent-tool" for path in BY_NAME_ENDED}, {path: old.classify(path) for path in BY_NAME_ENDED})
        for path, text in BY_NAME_ENDED.items():
            with self.subTest(path=path):
                with self.assertRaises(matrix.NativeAcceptanceMatrixError):
                    self.link(path, text)
                self.assertEqual("historical", self.row(self.head())["status"])
                self.assertEqual("host-tool", reuse._ScopedInputs(self.root, self.original, self.head()).classify(path))

    def test_an_unrelated_tool_still_keeps_the_link(self):
        link = self.link("agent_tools/native_package_release_report.py")
        self.assertEqual(["agent-tool"], [entry["class"] for entry in link["changedPaths"]])
        self.assertEqual("passed", self.row(self.head())["status"])


if __name__ == "__main__":
    unittest.main()

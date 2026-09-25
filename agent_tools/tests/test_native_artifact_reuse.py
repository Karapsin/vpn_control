from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from agent_tools import native_artifact_registry as registry
from agent_tools import native_artifact_reuse as reuse


class NativeArtifactReuseImportTest(unittest.TestCase):
    def test_mcp_script_style_import_from_agent_tools_directory(self) -> None:
        agent_tools_directory = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, "-c",
                                 "import native_artifact_reuse; assert native_artifact_reuse.artifact_set_freeze"],
                                cwd=agent_tools_directory, capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_package_import_exposes_public_api(self) -> None:
        self.assertTrue(callable(reuse.artifact_set_freeze))
        self.assertTrue(callable(reuse.artifact_set_verify))
        self.assertTrue(callable(reuse.artifact_reuse_check))


@unittest.skipIf(os.name == "nt", "private artifact index requires POSIX admission")
class NativeArtifactReuseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.org")
        self.git("config", "user.name", "Test")
        (self.root / "gradle.properties").write_text("vpnControlVersion=2.1.18\n", encoding="utf-8")
        (self.root / "src.kt").write_text("val x = 1\n", encoding="utf-8")
        (self.root / "runtime.bin").write_bytes(b"runtime-v1")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "guide.md").write_text("guide\n", encoding="utf-8")
        (self.root / "tests").mkdir()
        (self.root / "tests" / "smoke.py").write_text("assert True\n", encoding="utf-8")
        self.commit()
        self.source = self.head()
        self.package = self.base / "package.bin"
        self.package.write_bytes(b"package-v1")
        self.registered = self.register(self.package, self.source)
        self.value = {
            "sourceSha": self.source,
            "packages": [{"artifactId": self.registered["artifactId"],
                          "locationId": self.registered["locations"][0]["locationId"]}],
            "runtimePaths": ["runtime.bin"],
            "provenance": {"architecture": "x86_64", "signer": {"kind": "unsigned"}},
        }
        self.frozen = reuse.artifact_set_freeze(self.root, self.value)

    def git(self, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=self.root, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()

    def commit(self) -> None:
        self.git("add", "-A", "gradle.properties", "src.kt", "runtime.bin", "docs", "tests")
        self.git("commit", "-qm", "fixture")

    def head(self) -> str:
        return self.git("rev-parse", "HEAD")

    def register(self, path: Path, source: str) -> dict:
        raw = path.read_bytes()
        return registry.register_artifact(self.root, {
            "platform": "linux", "artifactKind": "desktop-package", "localPath": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            "evidenceClass": "local-verified", "sourceSha": source,
        })

    def decision(self, **kwargs: object) -> dict:
        return reuse.artifact_reuse_check(self.root, {"artifactSetId": self.frozen["artifactSetId"]}, **kwargs)

    def test_same_source_and_docs_test_commit_reuse_with_original_provenance(self) -> None:
        same = self.decision()
        self.assertEqual("same-source", same["decision"])
        self.assertFalse(same["nativeAdmissionReady"])
        self.assertTrue(same["ciRequired"])
        (self.root / "docs" / "guide.md").write_text("revised\n", encoding="utf-8")
        (self.root / "tests" / "smoke.py").write_text("assert 1\n", encoding="utf-8")
        self.commit()
        later = self.decision()
        self.assertEqual("verified-equivalent-product-inputs", later["decision"])
        self.assertEqual(self.source, later["originalSourceSha"])
        self.assertEqual(self.head(), later["currentSourceSha"])
        self.assertNotEqual(later["originalSourceSha"], later["currentSourceSha"])
        self.assertEqual(self.source, self.frozen["packages"][0]["sourceSha"])

    def test_changed_package_and_runtime_bytes_reject_reuse(self) -> None:
        self.package.write_bytes(b"tampered")
        self.assertEqual("rebuild-required", self.decision()["decision"])
        self.package.write_bytes(b"package-v1")
        (self.root / "runtime.bin").write_bytes(b"runtime-v2")
        self.assertEqual("rebuild-required", self.decision()["decision"])

    def test_source_build_version_and_dirty_product_reject_reuse(self) -> None:
        (self.root / "src.kt").write_text("val x = 2\n", encoding="utf-8")
        self.assertEqual("rebuild-required", self.decision()["decision"])
        self.commit()
        self.assertEqual("rebuild-required", self.decision()["decision"])
        (self.root / "gradle.properties").write_text("vpnControlVersion=2.1.19\n", encoding="utf-8")
        self.commit()
        self.assertEqual("rebuild-required", self.decision()["decision"])

    def test_package_source_and_mixed_set_cannot_freeze(self) -> None:
        later = "f" * 40
        second = self.base / "other.bin"
        second.write_bytes(b"other")
        registered = self.register(second, later)
        mixed = copy.deepcopy(self.value)
        mixed["packages"].append({"artifactId": registered["artifactId"],
                                  "locationId": registered["locations"][0]["locationId"]})
        with self.assertRaisesRegex(reuse.ArtifactReuseError, "sourceSha"):
            reuse.artifact_set_freeze(self.root, mixed)
        forged = copy.deepcopy(self.value)
        forged["sourceSha"] = later
        with self.assertRaisesRegex(reuse.ArtifactReuseError, "HEAD"):
            reuse.artifact_set_freeze(self.root, forged)

    def test_forged_manifest_and_caller_inputs_do_not_establish_reuse(self) -> None:
        forged = copy.deepcopy(self.frozen)
        forged["productInputs"]["runtimeFiles"][0]["sha256"] = "0" * 64
        self.assertEqual("mismatch", reuse.artifact_set_verify(self.root, forged)["verification"])
        with self.assertRaises(reuse.ArtifactReuseError):
            reuse.artifact_reuse_check(self.root, {"artifactSet": forged})
        forged_input = dict(self.value, productInputs={"buildInputs": "trusted"})
        with self.assertRaises(reuse.ArtifactReuseError):
            reuse.artifact_set_freeze(self.root, forged_input)

    def test_unsafe_paths_symlinks_and_non_allowlisted_tests_reject(self) -> None:
        bad = copy.deepcopy(self.value)
        bad["runtimePaths"] = ["../runtime.bin"]
        with self.assertRaises(reuse.ArtifactReuseError):
            reuse.artifact_set_freeze(self.root, bad)
        (self.root / "runtime-link").symlink_to(self.root / "runtime.bin")
        bad["runtimePaths"] = ["runtime-link"]
        with self.assertRaises(reuse.ArtifactReuseError):
            reuse.artifact_set_freeze(self.root, bad)
        (self.root / "runtime-link").unlink()
        (self.root / "tests" / "native_package.py").write_text("assert True\n", encoding="utf-8")
        self.commit()
        self.assertEqual("rebuild-required", self.decision()["decision"])

    def test_changed_document_symlink_rejects_even_when_path_is_allowlisted(self) -> None:
        (self.root / "docs" / "guide.md").unlink()
        (self.root / "docs" / "guide.md").symlink_to(self.root / "src.kt")
        self.commit()
        self.assertEqual("rebuild-required", self.decision()["decision"])

    def test_private_set_record_is_required_and_cannot_be_replaced_by_symlink(self) -> None:
        path = self.root / ".rag_index" / "native-artifact-sets" / (self.frozen["artifactSetId"] + ".json")
        path.unlink()
        path.symlink_to(self.package)
        self.assertEqual("mismatch", reuse.artifact_set_verify(self.root, self.frozen["artifactSetId"])["verification"])
        with self.assertRaises(reuse.ArtifactReuseError):
            self.decision()

    def test_native_inspector_is_separate_from_source_reuse(self) -> None:
        supplied = {"verified": True, "architecture": "x86_64", "signer": {"kind": "unsigned"}}
        inspected = self.decision(inspectors={"desktop-package": lambda _root, _package: supplied})
        self.assertEqual("same-source", inspected["decision"])
        self.assertTrue(inspected["nativeAdmissionReady"])
        supplied["architecture"] = "arm64"
        self.assertFalse(self.decision(inspectors={"desktop-package": lambda _root, _package: supplied})["nativeAdmissionReady"])


if __name__ == "__main__":
    unittest.main()

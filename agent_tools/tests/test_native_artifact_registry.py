from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import native_artifact_registry as registry


class NativeArtifactRegistryTest(unittest.TestCase):
    def local_record(self, artifact: Path, **extra: object) -> dict[str, object]:
        contents = artifact.read_bytes()
        return {
            "platform": "linux", "artifactKind": "desktop-package", "localPath": str(artifact),
            "sha256": hashlib.sha256(contents).hexdigest(), "size": len(contents),
            "evidenceClass": "local-verified", "sourceSha": "a" * 40, **extra,
        }

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_register_is_content_derived_idempotent_and_historical_lookup_does_not_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = root / "package.tar.gz"; artifact.write_bytes(b"original bytes")
            record = self.local_record(artifact)
            first = registry.register_artifact(root, record)
            second = registry.register_artifact(root, record)
            self.assertEqual(first, second)
            self.assertEqual("sha256-" + record["sha256"], first["artifactId"])
            artifact.write_bytes(b"tampered")
            found = registry.find_artifacts(root, {"platform": "linux"})
            self.assertEqual([first], found["matches"])
            checked = registry.verify_artifact(root, first["artifactId"])
            self.assertEqual("mismatch", checked["verification"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_register_rejects_stale_declared_bytes_before_creating_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = root / "package"; artifact.write_bytes(b"actual")
            record = self.local_record(artifact); record["sha256"] = "0" * 64
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "do not match"):
                registry.register_artifact(root, record)
            self.assertFalse((root / ".rag_index" / "native-artifacts").exists())

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_unlinked_artifact_remains_historical_and_verifies_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = root / "package"; artifact.write_bytes(b"actual")
            registered = registry.register_artifact(root, self.local_record(artifact))
            artifact.unlink()
            historical = registry.find_artifacts(root, {"artifactId": registered["artifactId"]})
            self.assertEqual(registered["artifactId"], historical["matches"][0]["artifactId"])
            self.assertEqual("missing-or-unsafe", registry.verify_artifact(root, registered["artifactId"])["verification"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_first_use_directory_creation_race_revalidates_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "private"
            original_mkdir = Path.mkdir

            def competing_mkdir(path: Path, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
                if path == target and not path.exists():
                    original_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)
                    raise FileExistsError()
                original_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)

            with mock.patch.object(Path, "mkdir", competing_mkdir):
                registry._ensure_private_directory(target)
            self.assertTrue(target.is_dir())

    def test_stream_rejects_same_size_in_place_timestamp_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"; artifact.write_bytes(b"same-size")
            original_fstat = os.fstat; calls = 0

            def changing_fstat(fd: int) -> os.stat_result:
                nonlocal calls
                calls += 1
                if calls == 2:
                    snapshot = original_fstat(fd)
                    os.utime(artifact, ns=(snapshot.st_atime_ns, snapshot.st_mtime_ns + 1_000_000_000))
                return original_fstat(fd)

            with mock.patch.object(registry.os, "fstat", side_effect=changing_fstat):
                with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "changed"):
                    registry._stream_local_bytes(artifact)

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_same_content_can_have_multiple_immutable_locations_but_source_conflicts_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); one = root / "one"; two = root / "two"
            one.write_bytes(b"same"); two.write_bytes(b"same")
            first = registry.register_artifact(root, self.local_record(one))
            second = registry.register_artifact(root, self.local_record(two))
            self.assertEqual(first["artifactId"], second["artifactId"])
            self.assertEqual(2, len(second["locations"]))
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "locationId is required"):
                registry.verify_artifact(root, first["artifactId"])
            self.assertEqual("verified", registry.verify_artifact(root, first["artifactId"],
                                                                   second["locations"][1]["locationId"])["verification"])
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "conflicting"):
                registry.register_artifact(root, self.local_record(two, sourceSha="b" * 40))

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires extra privilege")
    def test_source_identity_and_path_hazards_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = root / "real"; artifact.write_bytes(b"bytes")
            malformed = self.local_record(artifact, sourceSha="ABC")
            with self.assertRaises(registry.NativeArtifactRegistryError):
                registry._normalize_registration(malformed)
            linked = root / "link"; linked.symlink_to(artifact)
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "symlink"):
                registry._normalize_registration(self.local_record(linked))

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_corrupt_or_interrupted_index_entry_never_returns_partial_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = root / "artifact"; artifact.write_bytes(b"bytes")
            registered = registry.register_artifact(root, self.local_record(artifact))
            entry = root / ".rag_index" / "native-artifacts" / (registered["artifactId"] + ".json")
            entry.write_text('{"schemaVersion":1,', encoding="utf-8")
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "corrupt"):
                registry.find_artifacts(root)
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "corrupt"):
                registry.verify_artifact(root, registered["artifactId"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_interrupted_atomic_staging_file_is_not_historical_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry.find_artifacts(root)
            staging = root / ".rag_index" / "native-artifacts" / ".tmp-123-abcd"
            staging.write_bytes(b'{"partial":')
            result = registry.find_artifacts(root)
            self.assertEqual([], result["matches"])
            self.assertFalse(staging.exists())

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_schema1_record_migrates_to_schema2_without_losing_verified_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = root / "legacy"; artifact.write_bytes(b"legacy bytes")
            original = registry.register_artifact(root, self.local_record(artifact))
            entry = root / ".rag_index" / "native-artifacts" / (original["artifactId"] + ".json")
            legacy = {"schemaVersion": 1, **{key: value for key, value in original.items() if key != "locations"},
                      **self.local_record(artifact)}
            entry.write_text(json.dumps(legacy, sort_keys=True), encoding="utf-8")
            artifact.unlink()
            migrated = registry.find_artifacts(root, {"artifactId": original["artifactId"]})["matches"][0]
            self.assertEqual(1, len(migrated["locations"]))
            self.assertEqual(2, json.loads(entry.read_text(encoding="utf-8"))["schemaVersion"])
            self.assertEqual("missing-or-unsafe", registry.verify_artifact(root, original["artifactId"])["verification"])

    @unittest.skipIf(os.name == "nt", "private registry writes require POSIX ownership admission")
    def test_remote_evidence_is_explicit_and_never_claims_local_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); digest = hashlib.sha256(b"remote").hexdigest()
            remote = {
                "platform": "windows", "artifactKind": "msi", "sha256": digest, "size": 6,
                "evidenceClass": "unverified-remote", "hostAlias": "build-win", "remotePath": "/private/out/app.msi",
                "receipt": "receipt-1", "sourceFingerprint": "b" * 64,
            }
            stored = registry.register_artifact(root, remote)
            checked = registry.verify_artifact(root, stored["artifactId"])
            self.assertEqual("unverified-remote", checked["verification"])
            self.assertNotIn("localPath", stored)
            remote.pop("receipt")
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "requires"):
                registry.register_artifact(root, remote)

    def test_malformed_query_and_bounds_are_rejected(self) -> None:
        for query in ({"limit": 0}, {"limit": 101}, {"path": "/anything"}, {"sourceSha": "A" * 40}):
            with self.subTest(query=query), self.assertRaises(registry.NativeArtifactRegistryError):
                registry._normalize_query(query)

    @unittest.skipUnless(os.name == "nt", "Windows-only private-directory admission guard")
    def test_windows_mutation_is_explicitly_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError, "unsupported on Windows"):
                registry.register_artifact(Path(temporary), {
                    "platform": "windows", "artifactKind": "msi", "localPath": str(Path(temporary) / "missing"),
                    "sha256": "0" * 64, "size": 0, "evidenceClass": "local-verified",
                })


if __name__ == "__main__":
    unittest.main()

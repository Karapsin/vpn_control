"""Actual bounded read-only artifact-index custody; no native admission."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import native_acceptance_overview as overview
from agent_tools import native_artifact_registry as registry


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX descriptor custody")
class ArtifactIndexCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS exposes /var via an OS symlink; use the actual TempFS ancestry
        # so the production nofollow custody remains strict.
        self.root = Path(self.temp.name).resolve()
        self.source = "a" * 40
        self.package = self.root / "fixture.bin"
        raw = b"SOURCE-ONLY-INERT-NOT-A-NATIVE-PACKAGE"
        self.package.write_bytes(raw)
        registered = registry.register_artifact(self.root, {
            "platform": "android", "artifactKind": "package", "localPath": str(self.package),
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "sourceSha": self.source, "evidenceClass": "local-verified"})
        self.identifier = registered["artifactId"]
        self.index = self.root / ".rag_index/native-artifacts"
        self.path = self.index / (self.identifier + ".json")

    def read(self):
        return overview.read_artifact_index(self.root, self.source, registry)

    def after_identity(self, mutation):
        original = registry._identity
        fired = []
        def identity(value):
            result = original(value)
            if not fired:
                fired.append(True)
                mutation()
            return result
        with mock.patch.object(registry, "_identity", side_effect=identity):
            with self.assertRaises(ValueError):
                self.read()
        self.assertEqual([True], fired)

    def test_actual_registered_record_read_is_pure_and_preserves_source(self):
        before = self.path.read_bytes()
        # No normal writer, cleanup, or migration is allowed by this view.
        with mock.patch.object(registry, "_prepare_registry", side_effect=AssertionError("writer called")), \
             mock.patch.object(registry, "_cleanup_temporary", side_effect=AssertionError("cleanup called")):
            result = self.read()
        self.assertEqual(self.source, result["records"][self.identifier]["sourceSha"])
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(self.identifier, result["matches"][0]["artifactId"])

    def test_parser_time_named_same_bytes_exchange_refuses(self):
        def exchange():
            original = self.path.read_bytes()
            replacement = self.root / "replacement"
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            replacement.replace(self.path)
        self.after_identity(exchange)

    def test_parser_time_same_inode_content_change_refuses(self):
        def mutate():
            before = self.path.stat()
            self.path.write_bytes(self.path.read_bytes().replace(b'"android"', b'"windows"'))
            os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.after_identity(mutate)

    def test_parser_time_parent_exchange_preserving_record_inode_refuses(self):
        original_inode = self.path.stat().st_ino
        def exchange():
            saved = self.index.with_name("retained-index")
            self.index.rename(saved)
            self.index.mkdir(mode=0o700)
            (saved / self.path.name).rename(self.path)
            self.assertEqual(original_inode, self.path.stat().st_ino)
        self.after_identity(exchange)

    def test_parser_time_root_exchange_preserving_index_refuses(self):
        def exchange():
            saved = self.root.with_name(self.root.name + "-retained")
            self.root.rename(saved)
            self.addCleanup(lambda: saved.rmdir())
            self.root.mkdir(mode=0o700)
            (saved / ".rag_index").rename(self.root / ".rag_index")
            (saved / self.package.name).rename(self.package)
        self.after_identity(exchange)

    def test_parser_time_file_mode_and_link_changes_refuse(self):
        self.after_identity(lambda: self.path.chmod(0o644))
        self.path.chmod(0o600)
        self.after_identity(lambda: os.link(self.path, self.root / "extra-link"))

    def test_parser_time_directory_mode_and_membership_changes_refuse(self):
        self.after_identity(lambda: self.index.chmod(0o755))
        self.index.chmod(0o700)
        self.after_identity(lambda: (self.index / "incomplete").write_bytes(b"partial"))

    def test_closing_last_body_read_late_exchange_refuses(self):
        real = os.pread
        count = []
        inode = self.path.stat().st_ino
        def late(fd, limit, offset):
            raw = real(fd, limit, offset)
            if os.fstat(fd).st_ino == inode and offset == 0:
                count.append(True)
                if len(count) == 2:
                    replacement = self.root / "late-replacement"
                    replacement.write_bytes(raw)
                    replacement.chmod(0o600)
                    replacement.replace(self.path)
            return raw
        with mock.patch.object(os, "pread", side_effect=late):
            with self.assertRaises(ValueError):
                self.read()
        self.assertEqual(2, len(count))

    def test_actual_last_index_parent_stat_unlink_refuses(self):
        original = os.stat
        fired = []
        def unlink_after_parent_observation(path, *args, **kwargs):
            observed = original(path, *args, **kwargs)
            if path == "native-artifacts" and kwargs.get("dir_fd") is not None and not fired:
                fired.append(True)
                self.path.unlink()
            return observed
        with mock.patch.object(os, "stat", side_effect=unlink_after_parent_observation):
            with self.assertRaises((ValueError, OSError)):
                self.read()
        self.assertEqual([True], fired)
        self.assertFalse(self.path.exists())

    def test_symlink_and_multilink_record_refuse_before_parser(self):
        saved = self.root / "saved-record"
        self.path.rename(saved)
        self.path.symlink_to(saved)
        with mock.patch.object(registry, "_identity", side_effect=AssertionError("parser called")):
            with self.assertRaises((ValueError, OSError)):
                self.read()
        self.path.unlink()
        os.link(saved, self.path)
        with mock.patch.object(registry, "_identity", side_effect=AssertionError("parser called")):
            with self.assertRaises(ValueError):
                self.read()

    def test_missing_index_does_not_create_private_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual({"matches": [], "records": {}}, overview.read_artifact_index(root, self.source, registry))
            self.assertFalse((root / ".rag_index").exists())

    def test_oversized_record_and_foreign_owner_refuse_before_parser(self):
        original = self.path.read_bytes()
        self.path.write_bytes(b"x" * (registry.MAX_RECORD_BYTES + 1))
        with mock.patch.object(registry, "_identity", side_effect=AssertionError("parser called")):
            with self.assertRaises(ValueError):
                self.read()
        self.path.write_bytes(original)
        with mock.patch.object(os, "getuid", return_value=os.getuid() + 1), \
             mock.patch.object(registry, "_identity", side_effect=AssertionError("parser called")):
            with self.assertRaises(ValueError):
                self.read()

    def test_duplicate_schema_keys_are_refused_without_migration(self):
        original = self.path.read_bytes()
        self.path.write_bytes(b'{"schemaVersion":1,' + original[1:])
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.read()
        self.assertEqual(before, self.path.read_bytes())


if __name__ == "__main__":
    unittest.main()

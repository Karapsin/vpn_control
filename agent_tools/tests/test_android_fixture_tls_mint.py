import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from cryptography import x509

from agent_tools import android_fixture_tls_mint as mint
from agent_tools import android_native_fixture


PLAN = {"sourceSha": "d" * 40, "baseArtifactId": "sha256-" + "3" * 64,
        "baseVersion": "2.2.2", "baseCode": 16840, "baseSignerSha256": "a" * 64,
        "targetArtifactId": "sha256-" + "2" * 64, "targetVersion": "2.2.3",
        "targetCode": 16860, "targetSha256": "2" * 64, "targetSize": 45026948,
        "endpoint": android_native_fixture.endpoint_contract(), "deviceMutationAllowed": False}
CAMPAIGN = "123e4567-e89b-42d3-a456-426614174000"
NOW = datetime.datetime(2026, 10, 3, 20, 34, tzinfo=datetime.timezone.utc)


class AndroidFixtureTlsMintTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name) / "private"
        self.parent.mkdir(mode=0o700)
        os.chmod(self.parent, 0o700)

    def tearDown(self):
        self.temp.cleanup()

    def mint(self, **kwargs):
        return mint.mint(self.parent, CAMPAIGN, PLAN, now=NOW,
                         uuid_factory=lambda: uuid.UUID(CAMPAIGN), **kwargs)

    def test_mints_short_lived_localhost_certificates_and_nonsecret_receipt(self):
        result = mint.mint(self.parent, CAMPAIGN, PLAN, now=NOW, validity_seconds=600,
                           uuid_factory=lambda: uuid.UUID(CAMPAIGN))
        directory = Path(result["directory"])
        self.assertEqual(0o700, directory.stat().st_mode & 0o777)
        self.assertEqual({"ca-key.pem", "ca.pem", "leaf-key.pem", "leaf.pem", "receipt.json"},
                         {item.name for item in directory.iterdir()})
        self.assertEqual(0o600, (directory / "leaf-key.pem").stat().st_mode & 0o777)
        leaf = x509.load_pem_x509_certificate((directory / "leaf.pem").read_bytes())
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("localhost", sans.get_values_for_type(x509.DNSName))
        self.assertIn("github.com", sans.get_values_for_type(x509.DNSName))
        self.assertEqual(["127.0.0.1"], [str(value) for value in sans.get_values_for_type(x509.IPAddress)])
        receipt = result["receipt"]
        required = {key: value for key, value in PLAN.items() if key not in {"endpoint", "deviceMutationAllowed"}}
        self.assertEqual(required, {key: receipt["sourceFacts"][key] for key in required})
        self.assertNotIn("PRIVATE KEY", json.dumps(receipt))
        self.assertEqual("2026-10-03T20:44:00Z", receipt["notAfter"])

    def test_existing_uuid_directory_never_overwrites(self):
        existing = self.parent / ("android-fixture-tls-" + CAMPAIGN)
        existing.mkdir(mode=0o700)
        sentinel = existing / "sentinel"
        sentinel.write_text("keep")
        with self.assertRaises(FileExistsError):
            self.mint()
        self.assertEqual("keep", sentinel.read_text())

    def test_symlink_parent_is_rejected_before_key_generation(self):
        other = Path(self.temp.name) / "other"
        other.mkdir(mode=0o700)
        link = Path(self.temp.name) / "link"
        link.symlink_to(other, target_is_directory=True)
        with self.assertRaises(mint.FixtureTlsMintError):
            mint.mint(link, CAMPAIGN, PLAN, now=NOW)
        self.assertEqual([], list(other.iterdir()))

    def test_inner_symlink_collision_is_not_followed_or_overwritten(self):
        target = Path(self.temp.name) / "target"
        target.write_text("keep")
        def collide(directory):
            (directory / "ca-key.pem").symlink_to(target)
        with self.assertRaises(FileExistsError):
            self.mint(after_directory_create=collide)
        self.assertEqual("keep", target.read_text())
        capsule = self.parent / ("android-fixture-tls-" + CAMPAIGN)
        self.assertTrue((capsule / "ca-key.pem").is_symlink())

    def test_parent_replacement_is_detected_and_preserves_private_failed_capsule(self):
        moved = Path(self.temp.name) / "moved"
        def replace(_child):
            self.parent.rename(moved)
            self.parent.mkdir(mode=0o700)
            os.chmod(self.parent, 0o700)
        with self.assertRaisesRegex(mint.FixtureTlsMintError, "parent was replaced"):
            self.mint(after_directory_create=replace)
        self.assertTrue((moved / ("android-fixture-tls-" + CAMPAIGN)).is_dir())
        self.assertEqual([], list(self.parent.iterdir()))

    def test_child_name_replacement_is_detected_before_key_generation(self):
        moved = self.parent / "owned-capsule"
        foreign = self.parent / ("android-fixture-tls-" + CAMPAIGN)
        def replace(child):
            child.rename(moved)
            foreign.mkdir(mode=0o700)
            (foreign / "foreign").write_text("keep")
        with self.assertRaisesRegex(mint.FixtureTlsMintError, "output directory was replaced"):
            self.mint(after_directory_create=replace)
        self.assertEqual("keep", (foreign / "foreign").read_text())
        self.assertTrue(moved.is_dir())

    def test_partial_write_failure_preserves_owned_private_capsule(self):
        original = mint._write_all
        calls = 0
        def fail_once(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.write(fd, data[:1])
                raise OSError("synthetic partial write")
            original(fd, data)
        mint._write_all = fail_once
        try:
            with self.assertRaises(OSError):
                self.mint()
        finally:
            mint._write_all = original
        capsule = self.parent / ("android-fixture-tls-" + CAMPAIGN)
        self.assertTrue(capsule.is_dir())
        self.assertEqual(0o700, capsule.stat().st_mode & 0o777)
        self.assertEqual(0o600, (capsule / "ca-key.pem").stat().st_mode & 0o777)

    def test_final_named_leaf_substitution_is_refused_and_preserved(self):
        original = mint._write_once
        def substitute(fd, name, data):
            result = original(fd, name, data)
            if name == "leaf.pem":
                os.unlink(name, dir_fd=fd)
                replacement = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                try:
                    os.write(replacement, b"foreign leaf")
                    os.fsync(replacement)
                finally:
                    os.close(replacement)
            return result
        mint._write_once = substitute
        try:
            with self.assertRaisesRegex(mint.FixtureTlsMintError, "named file was replaced"):
                self.mint()
        finally:
            mint._write_once = original
        capsule = self.parent / ("android-fixture-tls-" + CAMPAIGN)
        self.assertEqual(b"foreign leaf", (capsule / "leaf.pem").read_bytes())

    def test_final_named_receipt_swap_is_refused_even_when_reader_stat_is_spoofed(self):
        named = self.parent / ("android-fixture-tls-" + CAMPAIGN) / "receipt.json"
        original_open, original_fstat = mint.os.open, mint.os.fstat
        reads = 0
        target_fd = None
        frozen = None
        def opened(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal reads, target_fd
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            if path == "receipt.json" and flags & os.O_ACCMODE == os.O_RDONLY:
                reads += 1
                if reads == 2:  # Second receipt read is the final verifier reader.
                    target_fd = descriptor
            return descriptor
        def stated(descriptor):
            nonlocal frozen
            value = original_fstat(descriptor)
            if descriptor == target_fd:
                if frozen is None:
                    frozen = value
                    os.unlink(named)
                    replacement = original_open(named, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        os.write(replacement, b"foreign receipt")
                        os.fsync(replacement)
                    finally:
                        os.close(replacement)
                return frozen
            return value
        mint.os.open, mint.os.fstat = opened, stated
        try:
            with self.assertRaisesRegex(mint.FixtureTlsMintError, "named file entry was replaced"):
                self.mint()
        finally:
            mint.os.open, mint.os.fstat = original_open, original_fstat
        self.assertEqual(b"foreign receipt", named.read_bytes())

    def test_parent_directory_is_fsynced_before_creation_hook_and_before_return(self):
        original = mint.os.fsync
        calls = []
        def recorded(fd):
            calls.append(fd)
            return original(fd)
        mint.os.fsync = recorded
        try:
            def after_create(_directory):
                self.assertGreaterEqual(len(calls), 1)
            self.mint(after_directory_create=after_create)
        finally:
            mint.os.fsync = original
        # One parent fsync occurs before the hook; publication adds a later one.
        self.assertGreaterEqual(len(calls), 7)

    def test_invalid_plan_and_long_validity_are_rejected_without_files(self):
        invalid = dict(PLAN, targetCode=PLAN["baseCode"])
        with self.assertRaises(mint.FixtureTlsMintError):
            mint.mint(self.parent, CAMPAIGN, invalid, now=NOW)
        with self.assertRaises(mint.FixtureTlsMintError):
            self.mint(validity_seconds=24 * 60 * 60 + 1)
        self.assertEqual([], list(self.parent.iterdir()))

    def test_plan_rejects_mismatched_artifact_signer_version_and_code(self):
        invalids = [
            dict(PLAN, targetArtifactId="sha256-" + "f" * 64),
            dict(PLAN, baseSignerSha256="a" * 40),
            dict(PLAN, targetVersion="2.2.20"),
            dict(PLAN, targetCode=16861),
        ]
        for plan in invalids:
            with self.assertRaises(mint.FixtureTlsMintError):
                mint.mint(self.parent, CAMPAIGN, plan, now=NOW)
        self.assertEqual([], list(self.parent.iterdir()))

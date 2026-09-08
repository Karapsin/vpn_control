import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from android_fixture_transport import parse_reverse_inventory
from android_fixture_trust import (
    android_ca_store_filename,
    certificate_validity_epochs,
    require_android_certificate_store_layout,
    require_device_time_within_certificates,
    secure_private_fixture_files,
    zygote_bind_mount_argv,
)


class AndroidFixtureTrustTest(unittest.TestCase):
    api29_cacerts_label = "u:object_r:system_security_cacerts_file:s0"

    def create_certificate_pair(self, directory: Path) -> tuple[Path, Path]:
        ca = directory / "ca.pem"
        leaf = directory / "leaf.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "1", "-subj", "/CN=fixture trust test",
                "-keyout", str(directory / "private.pem"), "-out", str(ca),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", "/CN=github.com", "-keyout", str(directory / "leaf-private.pem"),
                "-out", str(directory / "leaf.csr"),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", str(directory / "leaf.csr"), "-CA", str(ca),
                "-CAkey", str(directory / "private.pem"), "-CAcreateserial", "-out", str(leaf),
                "-days", "1", "-sha256",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ca, leaf

    def test_android_store_name_uses_openssl_legacy_subject_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            certificate, _ = self.create_certificate_pair(directory)
            old_hash = subprocess.run(
                ["openssl", "x509", "-in", str(certificate), "-noout", "-subject_hash_old"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            current_hash = subprocess.run(
                ["openssl", "x509", "-in", str(certificate), "-noout", "-hash"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            self.assertNotEqual(current_hash, old_hash)
            self.assertEqual(f"{old_hash}.0", android_ca_store_filename(certificate))

    def test_device_time_must_be_within_both_certificate_windows(self):
        with tempfile.TemporaryDirectory() as temporary:
            ca, leaf = self.create_certificate_pair(Path(temporary))
            not_before, not_after = certificate_validity_epochs(leaf)
            with self.assertRaisesRegex(RuntimeError, "not valid"):
                require_device_time_within_certificates(not_before - 1, ca, leaf)
            require_device_time_within_certificates(not_before, ca, leaf)
            with self.assertRaisesRegex(RuntimeError, "not valid"):
                require_device_time_within_certificates(not_after, ca, leaf)

    def test_device_time_checks_ca_and_leaf_independently(self):
        with patch(
            "android_fixture_trust.certificate_validity_epochs", side_effect=[(0, 10), (20, 30)]
        ):
            with self.assertRaisesRegex(RuntimeError, "not valid"):
                require_device_time_within_certificates(5, Path("ca"), Path("leaf"))
        with patch(
            "android_fixture_trust.certificate_validity_epochs", side_effect=[(20, 30), (0, 10)]
        ):
            with self.assertRaisesRegex(RuntimeError, "not valid"):
                require_device_time_within_certificates(5, Path("ca"), Path("leaf"))

    def test_certificate_validity_parser_requires_openssl_gmt(self):
        result = subprocess.CompletedProcess(
            [], 0, stdout="notBefore=Sep  8 19:03:50 2026 GMT\nnotAfter=Sep  9 19:03:50 2026 GMT\n"
        )
        with patch("android_fixture_trust.subprocess.run", return_value=result):
            self.assertEqual((1788894230, 1788980630), certificate_validity_epochs(Path("fixture.pem")))
        result = subprocess.CompletedProcess(
            [], 0, stdout="notBefore=Sep  8 19:03:50 2026 UTC\nnotAfter=Sep  9 19:03:50 2026 UTC\n"
        )
        with patch("android_fixture_trust.subprocess.run", return_value=result), self.assertRaises(ValueError):
            certificate_validity_epochs(Path("fixture.pem"))

    def test_private_parent_does_not_make_mounted_store_private(self):
        require_android_certificate_store_layout(
            0o700, 0o755, 0o644, self.api29_cacerts_label, self.api29_cacerts_label
        )
        with self.assertRaisesRegex(RuntimeError, "Mounted"):
            require_android_certificate_store_layout(
                0o700, 0o700, 0o600, self.api29_cacerts_label, self.api29_cacerts_label
            )
        with self.assertRaisesRegex(RuntimeError, "SELinux"):
            require_android_certificate_store_layout(
                0o700, 0o755, 0o644, "u:object_r:shell_data_file:s0", self.api29_cacerts_label
            )

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits are host-specific")
    def test_private_file_security_never_changes_child_directory_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            fixture.mkdir(mode=0o700)
            private_file = fixture / "server.log"
            private_file.write_text("safe")
            child_directory = fixture / "nested"
            child_directory.mkdir(mode=0o700)
            secure_private_fixture_files([private_file])
            self.assertEqual(0o600, private_file.stat().st_mode & 0o777)
            self.assertEqual(0o700, child_directory.stat().st_mode & 0o777)
            with self.assertRaises(ValueError):
                secure_private_fixture_files([child_directory])

    def test_private_file_security_rejects_directory_before_changing_any_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            fixture.mkdir()
            private_file = fixture / "server.log"
            private_file.write_text("safe")
            child_directory = fixture / "nested"
            child_directory.mkdir()
            with self.assertRaises(ValueError):
                secure_private_fixture_files([private_file, child_directory])
            self.assertEqual("safe", private_file.read_text())
            self.assertTrue(child_directory.is_dir())

    def test_blank_adb_reverse_output_is_empty_inventory(self):
        self.assertEqual({}, parse_reverse_inventory("\n"))

    def test_zygote_bind_mount_argv_has_required_command_separator(self):
        self.assertEqual(
            [
                "nsenter", "-t", "177", "-m", "--", "mount", "--bind",
                "/data/local/tmp/fixture-cacerts", "/system/etc/security/cacerts",
            ],
            zygote_bind_mount_argv(
                "177", "/data/local/tmp/fixture-cacerts", "/system/etc/security/cacerts"
            ),
        )

    def test_zygote_bind_mount_argv_rejects_non_namespace_inputs(self):
        for pid, source, target in (
            ("0", "/data/local/tmp/fixture", "/system/etc/security/cacerts"),
            ("17x", "/data/local/tmp/fixture", "/system/etc/security/cacerts"),
            ("177", "relative", "/system/etc/security/cacerts"),
            ("177", "/data/local/tmp/fixture", "relative"),
        ):
            with self.subTest(pid=pid, source=source, target=target), self.assertRaises(ValueError):
                zygote_bind_mount_argv(pid, source, target)


if __name__ == "__main__":
    unittest.main()

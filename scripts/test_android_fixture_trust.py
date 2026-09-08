import subprocess
import tempfile
import unittest
from pathlib import Path

from android_fixture_trust import android_ca_store_filename, zygote_bind_mount_argv


class AndroidFixtureTrustTest(unittest.TestCase):
    def test_android_store_name_uses_openssl_legacy_subject_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            certificate = directory / "ca.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                    "-days", "1", "-subj", "/CN=fixture trust test",
                    "-keyout", str(directory / "private.pem"), "-out", str(certificate),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
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

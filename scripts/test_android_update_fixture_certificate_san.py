import json
import socket
import ssl
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.integration.android_update_fixture import launch_supervised_fixture


class AndroidUpdateFixtureCertificateSanTest(unittest.TestCase):
    def create_certificate(self, directory: Path, *, san: bool) -> tuple[Path, Path]:
        certificate = directory / "certificate.pem"
        private_key = directory / "private.pem"
        command = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=github.com", "-keyout", str(private_key), "-out", str(certificate),
        ]
        if san:
            command.extend(["-addext", "subjectAltName=DNS:github.com"])
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return certificate, private_key

    def stop(self, process) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def test_cn_only_leaf_is_rejected_before_supervisor_creates_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = root / "update.apk"
            apk.write_bytes(b"fixture")
            certificate, private_key = self.create_certificate(root, san=False)
            ready, log, receipt = root / "ready.json", root / "fixture.log", root / "receipt.json"

            with self.assertRaisesRegex(ValueError, "subjectAltName github.com"):
                launch_supervised_fixture(apk, "2.3.8", 17360, certificate, private_key, ready, log, receipt)

            self.assertFalse(ready.exists())
            self.assertFalse(log.exists())
            self.assertFalse(receipt.exists())

    def test_san_leaf_serves_manifest_to_hostname_verifying_client(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = root / "update.apk"
            apk.write_bytes(b"fixture")
            certificate, private_key = self.create_certificate(root, san=True)
            ready, log, receipt = root / "ready.json", root / "fixture.log", root / "receipt.json"
            process = launch_supervised_fixture(apk, "2.3.8", 17360, certificate, private_key, ready, log, receipt)
            try:
                port = json.loads(ready.read_text())["port"]
                context = ssl.create_default_context(cafile=str(certificate))
                with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                    connection.sendall(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
                    self.assertIn(b"200 Connection Established", connection.recv(1024))
                    with context.wrap_socket(connection, server_hostname="github.com") as tls:
                        tls.sendall(
                            b"GET /Karapsin/vpn_control/releases/latest/download/update-manifest.json HTTP/1.1\r\n"
                            b"Host: github.com\r\nConnection: close\r\n\r\n"
                        )
                        response = bytearray()
                        while True:
                            block = tls.recv(4096)
                            if not block:
                                break
                            response.extend(block)
                self.assertIn(b"200 OK", response)
                self.assertIn(b'"displayVersion":"2.3.8"', response)
            finally:
                self.stop(process)


if __name__ == "__main__":
    unittest.main()

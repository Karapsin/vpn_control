import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.integration.android_update_fixture import (
    APK_PATH, MANIFEST_PATH, FixtureReadinessError, fixture_environment,
    launch_supervised_fixture, make_manifest, select_resource,
)
from scripts.test_android_update_fixture_certificate_san import AndroidUpdateFixtureCertificateSanTest


class AndroidUpdateFixtureTest(unittest.TestCase):
    def write_fixture_apk(self, path: Path, *abis: str) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for abi in abis:
                archive.writestr(f"lib/{abi}/libfixture.so", b"fixture")

    def create_certificate_pair(self, directory: Path):
        certificate = directory / "certificate.pem"
        private_key = directory / "private.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=github.com", "-addext", "subjectAltName=DNS:github.com",
            "-keyout", str(private_key), "-out", str(certificate),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return certificate, private_key

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def wait_for_listener_to_close(self, port: int):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    pass
            except OSError:
                return
            time.sleep(0.05)
        self.fail("bounded fixture listener did not close")

    def test_fixture_serves_only_exact_trusted_paths_without_forwarding(self):
        self.assertEqual("manifest", select_resource("GET", MANIFEST_PATH, "github.com"))
        self.assertEqual("apk", select_resource("GET", APK_PATH, "github.com:443"))
        for method, path, host in (("POST", APK_PATH, "github.com"), ("GET", "/", "github.com"),
                                   ("GET", APK_PATH, "github.com.attacker.invalid"),
                                   ("GET", "https://elsewhere.invalid/", "github.com")):
            self.assertIsNone(select_resource(method, path, host))

    def test_manifest_hashes_exact_artifact_and_keeps_production_trust_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            self.write_fixture_apk(apk, "x86_64")
            expected_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
            expected_size = apk.stat().st_size
            result = make_manifest(apk, "2.1.3", 16460)
        asset = result["assets"][0]
        self.assertEqual(expected_hash, asset["sha256"])
        self.assertEqual("x86_64", asset["architecture"])
        self.assertEqual(expected_size, asset["sizeBytes"])
        self.assertTrue(asset["downloadUrl"].startswith("https://github.com/Karapsin/vpn_control/"))
        self.assertEqual(16460, result["buildNumber"])

    def test_manifest_advertises_every_supported_payload_abi(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "multi.apk"
            self.write_fixture_apk(apk, "x86_64", "arm64-v8a")
            result = make_manifest(apk, "2.1.3", 16460)
        self.assertEqual(["arm64-v8a", "x86_64"], [asset["architecture"] for asset in result["assets"]])
        self.assertEqual(1, len({asset["sha256"] for asset in result["assets"]}))
        self.assertEqual(1, len({asset["sizeBytes"] for asset in result["assets"]}))

    def test_manifest_rejects_malformed_or_unsupported_native_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            malformed = root / "malformed.apk"
            malformed.write_bytes(b"not a zip")
            with self.assertRaisesRegex(ValueError, "readable ZIP archive"):
                make_manifest(malformed, "2.1.3", 16460)
            unsupported = root / "unsupported.apk"
            self.write_fixture_apk(unsupported, "mips")
            with self.assertRaisesRegex(ValueError, "no supported Android native library ABI"):
                make_manifest(unsupported, "2.1.3", 16460)
            symlink = root / "symlink.apk"
            with zipfile.ZipFile(symlink, "w", compression=zipfile.ZIP_STORED) as archive:
                link = zipfile.ZipInfo("lib/x86_64/libfixture.so")
                link.create_system = 3
                link.external_attr = 0o120777 << 16
                archive.writestr(link, b"elsewhere")
            with self.assertRaisesRegex(ValueError, "no supported Android native library ABI"):
                make_manifest(symlink, "2.1.3", 16460)

    def test_supervisor_cli_retains_live_fixture_after_returning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "update.apk"; self.write_fixture_apk(apk, "x86_64")
            certificate, private_key = self.create_certificate_pair(root)
            ready, log, receipt, stop = (root / "ready.json", root / "fixture.log",
                                         root / "receipt.json", root / "stop")
            command = [
                sys.executable, str(Path(__file__).resolve().parent / "integration/android_update_fixture.py"),
                "--apk", str(apk), "--version", "2.3.5", "--build-number", "17300",
                "--certificate", str(certificate), "--private-key", str(private_key), "--ready-file", str(ready),
                "--supervise", "--log-file", str(log), "--receipt-file", str(receipt),
                "--serve-for-seconds", "30", "--stop-file", str(stop),
            ]
            environment = dict(os.environ)
            environment.pop("DYLD_INSERT_LIBRARIES", None)
            completed = subprocess.run(command, capture_output=True, text=True, env=environment)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertTrue(ready.is_file())
            recorded = json.loads(receipt.read_text())
            self.assertEqual("ready", recorded["state"])
            # A socket connection proves that the child retained by the supervisor
            # still owns a live listener after the CLI process returned.  PID probes
            # are not a safe Windows liveness check and can observe a reused PID.
            with socket.create_connection(("127.0.0.1", recorded["port"]), timeout=5):
                pass
            if os.name == "posix":
                self.assertEqual(0o600, ready.stat().st_mode & 0o777)
                self.assertEqual(0o600, log.stat().st_mode & 0o777)
                self.assertEqual(0o600, receipt.stat().st_mode & 0o777)
            # The test owns this shutdown signal; no PID is targeted after its creating
            # process has returned, because Windows can recycle PID values.
            stop.write_text("stop\n", encoding="utf-8")
            self.wait_for_listener_to_close(recorded["port"])

    def test_supervisor_child_environment_removes_host_injection_and_normalizes_path(self):
        environment = fixture_environment({"DYLD_INSERT_LIBRARIES": "host-only", "PATH": "/host-tools"})
        self.assertNotIn("DYLD_INSERT_LIBRARIES", environment)
        self.assertEqual(os.defpath, environment["PATH"])

    def test_supervisor_records_child_exit_and_log_before_gating_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "update.apk"; self.write_fixture_apk(apk, "x86_64")
            certificate, _ = self.create_certificate_pair(root)
            ready, log, receipt = root / "ready.json", root / "fixture.log", root / "receipt.json"
            with self.assertRaises(FixtureReadinessError) as raised:
                launch_supervised_fixture(apk, "2.3.5", 17300, certificate, root / "missing-key.pem",
                                          ready, log, receipt)
            recorded = json.loads(receipt.read_text())
            self.assertEqual("exited", recorded["state"])
            self.assertIsInstance(recorded["exitCode"], int)
            self.assertEqual(str(log), recorded["logFile"])
            self.assertTrue(log.read_bytes())
            self.assertEqual(recorded, raised.exception.receipt)

    def test_supervisor_waits_for_a_partially_published_ready_file_to_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "update.apk"; self.write_fixture_apk(apk, "x86_64")
            certificate, private_key = self.create_certificate_pair(root)
            fixture = root / "partial_ready_fixture.py"
            fixture.write_text(
                "import json,sys,time\n"
                "from pathlib import Path\n"
                f"sys.path.insert(0,{str(Path(__file__).resolve().parents[1])!r})\n"
                "from scripts.integration.android_update_fixture import make_manifest\n"
                "v=sys.argv\n"
                "def value(flag): return v[v.index(flag)+1]\n"
                "ready=Path(value('--ready-file'))\n"
                "ready.write_text('{\\\"port\\\":', encoding='utf-8')\n"
                "time.sleep(.2)\n"
                "ready.write_text(json.dumps({'port':32123,'manifest':make_manifest(Path(value('--apk')),value('--version'),int(value('--build-number')))}),encoding='utf-8')\n"
                "while True: time.sleep(1)\n",
                encoding="utf-8",
            )
            ready, log, receipt = root / "ready.json", root / "fixture.log", root / "receipt.json"
            process = launch_supervised_fixture(apk, "2.3.5", 17300, certificate, private_key,
                                                ready, log, receipt, fixture_script=fixture)
            try:
                self.assertIsNone(process.poll())
                self.assertEqual("ready", json.loads(receipt.read_text())["state"])
            finally:
                self.stop(process)


if __name__ == "__main__":
    unittest.main()

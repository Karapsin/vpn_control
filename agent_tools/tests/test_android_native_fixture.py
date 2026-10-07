"""Fast causal admission for Android native acceptance package preparation."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

from agent_tools import android_native_fixture as fixture
from agent_tools import android_package_install, native_artifact_registry


SOURCE = "a" * 40
CAMPAIGN = "af8e5588-b7a6-4a57-bd5c-38de4561bf83"
BASE = fixture.BASE_ARTIFACT_ID
TARGET = "sha256-" + "b" * 64
SIGNER = "c" * 64


class AndroidNativeFixtureTest(unittest.TestCase):
    def test_dirty_checkout_cannot_claim_source_bound_fixture(self):
        with mock.patch.object(fixture, "_head", return_value=SOURCE), \
             mock.patch.object(fixture, "_clean", return_value=False):
            with self.assertRaisesRegex(ValueError, "source SHA"):
                fixture.prepare_requirements(".", SOURCE)

    def test_clean_status_disables_git_optional_writes(self):
        with mock.patch.object(fixture.subprocess, "run", return_value=mock.Mock(stdout="")) as run:
            self.assertTrue(fixture._clean(Path(".")))
        args = run.call_args.args[0]
        self.assertEqual(["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                          "--no-optional-locks", "status"], args[:7])
        self.assertEqual("0", run.call_args.kwargs["env"]["GIT_OPTIONAL_LOCKS"])

    def test_same_version_base_requires_higher_version_target(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "gradle.properties").write_text("vpnControlVersion=2.2.0\n")
            artifact = {"platform": "android", "artifactKind": "apk", "sha256": BASE[7:],
                        "sourceSha": "historical", "size": 100}
            verified = {"verification": "verified", "artifact": artifact,
                        "location": {"localPath": str(root / "base.apk")}}
            package = {"package": "com.kardinal.vpncontrol", "code": 16800,
                       "version": "2.2.0", "abi": "x86_64", "signerSha256": SIGNER, "debuggable": False}
            with mock.patch.object(fixture, "_head", return_value=SOURCE), \
                 mock.patch.object(fixture, "_clean", return_value=True), \
                 mock.patch.object(native_artifact_registry, "verify_artifact", return_value=verified), \
                 mock.patch.object(android_package_install, "_inspect_apk", return_value=package):
                planned = fixture.prepare_requirements(root, SOURCE)
            self.assertEqual("2.2.1", planned["targetVersion"])
            self.assertEqual(16820, planned["targetCode"])
            self.assertEqual([":app:assembleNativeFixture", "-PvpnControlVersion=2.2.1"], planned["targetBuildArgs"])
            self.assertFalse(planned["deviceMutationAllowed"])

    def test_clean_linked_source_plans_223_from_current_222_base_despite_dirty_coordinator(self):
        with tempfile.TemporaryDirectory() as raw:
            coordinator = Path(raw) / "coordinator"; coordinator.mkdir()
            source_root = Path(raw) / "clean-source"; source_root.mkdir()
            (source_root / "gradle.properties").write_text("vpnControlVersion=2.2.2\n")
            artifact = {"platform": "android", "artifactKind": "apk", "sha256": BASE[7:],
                        "sourceSha": SOURCE, "size": 100}
            package = {"package": "com.kardinal.vpncontrol", "code": 16840,
                       "version": "2.2.2", "abi": "x86_64", "signerSha256": SIGNER, "debuggable": False}
            with mock.patch.object(fixture, "_source_root", return_value=source_root) as bind, \
                    mock.patch.object(fixture, "_head", side_effect=lambda path: SOURCE if path == source_root else "dirty") as head, \
                    mock.patch.object(fixture, "_clean", side_effect=lambda path: path == source_root) as clean, \
                    mock.patch.object(fixture, "_artifact", return_value=(artifact, package)) as artifact_read:
                planned = fixture.prepare_requirements(coordinator, SOURCE, source_root=source_root)
            self.assertEqual("2.2.3", planned["targetVersion"])
            self.assertEqual(16860, planned["targetCode"])
            self.assertEqual([":app:assembleNativeFixture", "-PvpnControlVersion=2.2.3"], planned["targetBuildArgs"])
            bind.assert_called_once_with(coordinator.resolve(), source_root)
            self.assertEqual(head.call_args_list, [mock.call(source_root)])
            self.assertEqual(clean.call_args_list, [mock.call(source_root)])
            artifact_read.assert_called_once_with(coordinator.resolve(), BASE)

    def test_source_root_rejects_symlink_foreign_dirty_and_mismatched_before_artifact_read(self):
        with tempfile.TemporaryDirectory() as raw:
            coordinator = Path(raw) / "coordinator"; coordinator.mkdir()
            source_root = Path(raw) / "clean-source"; source_root.mkdir()
            (source_root / "gradle.properties").write_text("vpnControlVersion=2.2.2\n")
            link = Path(raw) / "source-link"; link.symlink_to(source_root, target_is_directory=True)
            with self.assertRaises(ValueError):
                fixture.prepare_requirements(coordinator, SOURCE, source_root=link)
            for common_pair, head, clean in ((("/foreign/.git", "/coordinator/.git"), SOURCE, True),
                                              (("/shared/.git", "/shared/.git"), SOURCE, False),
                                              (("/shared/.git", "/shared/.git"), "b" * 40, True)):
                with self.subTest(common_pair=common_pair, head=head, clean=clean), \
                        mock.patch.object(fixture, "_git_common_dir", side_effect=common_pair), \
                        mock.patch.object(fixture, "_head", return_value=head), \
                        mock.patch.object(fixture, "_clean", return_value=clean), \
                        mock.patch.object(fixture, "_artifact") as artifact_read:
                    with self.assertRaises(ValueError):
                        fixture.prepare_requirements(coordinator, SOURCE, source_root=source_root)
                    artifact_read.assert_not_called()

    def test_target_rejects_wrong_source_signer_and_version(self):
        requirements = {"sourceSha": SOURCE, "baseArtifactId": BASE, "baseSignerSha256": SIGNER,
                        "targetVersion": "2.2.1", "targetCode": 16820}
        item = {"platform": "android", "artifactKind": "apk", "sha256": TARGET[7:],
                "sourceSha": SOURCE, "size": 120}
        package = {"package": "com.kardinal.vpncontrol", "code": 16820,
                   "version": "2.2.1", "abi": "x86_64", "signerSha256": SIGNER, "debuggable": False}
        with mock.patch.object(fixture, "_head", return_value=SOURCE), \
             mock.patch.object(fixture, "_clean", return_value=True), \
             mock.patch.object(fixture, "prepare_requirements", return_value=requirements), \
             mock.patch.object(native_artifact_registry, "verify_artifact", return_value={
                 "verification": "verified", "artifact": item, "location": {"localPath": "/target.apk"}}), \
             mock.patch.object(android_package_install, "_inspect_apk", return_value=package):
            self.assertEqual(TARGET[7:], fixture.verify_target(".", requirements, TARGET)["targetSha256"])
            with mock.patch.object(fixture, "prepare_requirements", return_value={**requirements, "baseSignerSha256": "f" * 64}):
                with self.assertRaisesRegex(ValueError, "opening package plan changed"):
                    fixture.verify_target(".", requirements, TARGET)
            for changed_item, changed_package in (({**item, "sourceSha": "d" * 40}, package),
                                                  (item, {**package, "signerSha256": "e" * 64}),
                                                  (item, {**package, "version": "2.2.0"}),
                                                  (item, {**package, "debuggable": True})):
                with mock.patch.object(native_artifact_registry, "verify_artifact", return_value={
                    "verification": "verified", "artifact": changed_item, "location": {"localPath": "/target.apk"}}), \
                    mock.patch.object(android_package_install, "_inspect_apk", return_value=changed_package):
                    with self.assertRaises(ValueError):
                        fixture.verify_target(".", requirements, TARGET)

    def test_endpoint_is_fixed_https_and_private_plan_never_replaces(self):
        endpoint = fixture.endpoint_contract()
        self.assertEqual("https://localhost:18080/health", endpoint["healthUrl"])
        self.assertEqual("socks://127.0.0.1:18081#NativeFixture", endpoint["location"])
        self.assertFalse(endpoint["installerTargetAdmitted"])
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
            directory = Path(raw); directory.chmod(0o700)
            output = directory / "plan.json"
            fixture.write_private_plan(output, {"endpoint": endpoint, "deviceMutationAllowed": False})
            self.assertEqual(False, json.loads(output.read_text())["deviceMutationAllowed"])
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                fixture.write_private_plan(output, {})
            foreign = directory / "foreign"; foreign.mkdir(); foreign.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "not private"):
                fixture.write_private_plan(foreign / "plan.json", {})
            link = directory / "link"; link.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink ancestry"):
                fixture.write_private_plan(link / "plan.json", {})

    @unittest.skipUnless(shutil.which("openssl"), "TLS fixture needs openssl")
    def test_local_endpoint_proves_tls_and_rejects_foreign_socks_target(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); cert = root / "cert.pem"; key = root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                            "-keyout", str(key), "-out", str(cert)], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10)
            key.chmod(0o600)
            with fixture.LocalEndpoint(cert, key, CAMPAIGN) as endpoint:
                self.assertIsNotNone(endpoint.https)
                self.assertIsNotNone(endpoint.socks)
                https_port = endpoint.https.server_address[1]
                socks_port = endpoint.socks.server_address[1]
                with socket.create_connection(("127.0.0.1", socks_port), timeout=2) as connection:
                    connection.sendall(b"\x05\x01\x00")
                    self.assertEqual(b"\x05\x00", fixture._exact(connection, 2))
                    connection.sendall(b"\x05\x01\x00\x03\x09localhost" + (18080).to_bytes(2, "big"))
                    self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", fixture._exact(connection, 10))
                    context = ssl._create_unverified_context()
                    with context.wrap_socket(connection, server_hostname="localhost") as tls:
                        tls.sendall(b"GET /traffic HTTP/1.1\r\nHost: localhost:18080\r\nConnection: close\r\n\r\n")
                        received = b""
                        while part := tls.recv(4096):
                            received += part
                    self.assertIn(b"vpn-control-native-fixture", received)
                with socket.create_connection(("127.0.0.1", socks_port), timeout=2) as connection:
                    connection.sendall(b"\x05\x01\x00")
                    self.assertEqual(b"\x05\x00", fixture._exact(connection, 2))
                    connection.sendall(b"\x05\x01\x00\x03\x0bexample.com" + (18080).to_bytes(2, "big"))
                    self.assertEqual(b"", connection.recv(2))
                self.assertEqual("127.0.0.1", endpoint.https.server_address[0])
                self.assertEqual("127.0.0.1", endpoint.socks.server_address[0])
                self.assertEqual({"campaignId": CAMPAIGN, "socksConnected": 1, "socksRejected": 1, "health": 0,
                                  "traffic": 1, "subscription": 0}, endpoint.event_counts())
                endpoint.events.append({"campaignId": "another", "transport": "socks", "event": "connected"})
                self.assertEqual(1, endpoint.event_counts()["socksConnected"])
            with self.assertRaisesRegex(ValueError, "cannot be restarted"):
                endpoint.start()

    @unittest.skipUnless(shutil.which("openssl"), "TLS fixture needs openssl")
    def test_tls_input_swap_during_load_rejected_without_listener(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); cert = root / "cert.pem"; key = root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                            "-keyout", str(key), "-out", str(cert)], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10)
            key.chmod(0o600)
            original = ssl.SSLContext.load_cert_chain
            def mutate(context, certfile, keyfile):
                original(context, certfile, keyfile)
                key.write_bytes(key.read_bytes() + b"\n")
            with mock.patch.object(ssl.SSLContext, "load_cert_chain", mutate):
                endpoint = fixture.LocalEndpoint(cert, key, CAMPAIGN)
                with self.assertRaisesRegex(ValueError, "changed during SSL loading"):
                    endpoint.start()
            self.assertIsNone(endpoint.https)
            self.assertIsNone(endpoint.socks)


if __name__ == "__main__":
    unittest.main()

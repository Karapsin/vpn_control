import hashlib
import base64
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile
import ssl

import prepare_desktop_update_fixture
from prepare_desktop_update_fixture import (
    MAIN_CLASS, MANIFEST_PATH, VERSION_RESOURCE, file_hash, image_identity, load_resources,
    native_build, recover_macos_target_package, package_asset, prepare, runtime_identity, select_resource, source_entries,
    verified_offloaded_base_record,
    verify_sources, version_build, require_install_ready, discard_completed_stage_directory,
    desktop_install_arguments, require_selected_location, require_active_runtime, fixture_proxy_arguments,
    serve_connection, write_resource_response, FIXTURE_ENTRYPOINT_MODULES,
    fixture_entrypoint_modules, stage_fixture_entrypoint, validate_staged_fixture_entrypoint,
)
from test_fixture_environment import symlink_probe_available


class DesktopUpdateFixtureTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "macOS private stop intent uses POSIX descriptor and owner APIs")
    def test_macos_graceful_stop_receipt_requires_exact_private_intent(self):
        """A bare SIGTERM or replaced intent cannot claim a zero-exit stop."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "macos-parityaaaaaaa"
            correlation = "11111111-1111-4111-8111-111111111111"
            evidence = root / "state" / "acceptance-evidence" / correlation
            evidence.mkdir(parents=True)
            evidence.chmod(0o700)
            ready_path = evidence / "server-ready.json"
            ready = {"port": 53633, "fixtureReceiptSha256": "b" * 64,
                     "serverInstanceId": "22222222-2222-4222-8222-222222222222",
                     "serverPid": os.getpid(), "serverProcessStartIdentity": "darwin:123456:123"}
            prepare_desktop_update_fixture.write_private_ready_json(ready_path, ready)
            raw = ready_path.read_bytes()
            with self.assertRaises(ValueError):
                prepare_desktop_update_fixture.write_macos_graceful_exit(ready_path, raw)
            intent = {"schemaVersion": 1, "sourceSha": "a" * 40,
                      "correlationId": correlation, "scenario": "install",
                      "jobId": "33333333-3333-4333-8333-333333333333",
                      "operationId": "44444444-4444-4444-8444-444444444444",
                      "bootSessionUuid": "55555555-5555-4555-8555-555555555555",
                      "reservationId": "env-1234", "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                      "serverInstanceId": ready["serverInstanceId"], "serverPid": os.getpid(),
                      "serverProcessStartIdentity": ready["serverProcessStartIdentity"],
                      "readySha256": hashlib.sha256(raw).hexdigest(), "stopRequestCount": 1,
                      "port": ready["port"]}
            (evidence / "server-stop-intent.json").write_text(json.dumps(intent))
            (evidence / "server-stop-intent.json").chmod(0o600)
            receipt = prepare_desktop_update_fixture.write_macos_graceful_exit(ready_path, raw)
            self.assertEqual(0, receipt["serverExitCode"])
            self.assertEqual(1, receipt["stopRequestCount"])
            self.assertTrue(receipt["stopReceiptFinal"])
            self.assertEqual(receipt, json.loads((evidence / "server-stop.json").read_text()))

    @unittest.skipIf(os.name == "nt", "macOS private stop intent uses POSIX descriptor and owner APIs")
    def test_macos_graceful_stop_rejects_linked_or_wrong_generation_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            correlation = "11111111-1111-4111-8111-111111111111"
            evidence = Path(temporary) / "macos-parityaaaaaaa" / "state" / "acceptance-evidence" / correlation
            evidence.mkdir(parents=True)
            evidence.chmod(0o700)
            ready_file = evidence / "server-ready.json"
            ready = {"port": 53633, "fixtureReceiptSha256": "b" * 64,
                     "serverInstanceId": "22222222-2222-4222-8222-222222222222",
                     "serverPid": os.getpid(), "serverProcessStartIdentity": "darwin:123456:123"}
            prepare_desktop_update_fixture.write_private_ready_json(ready_file, ready)
            raw = ready_file.read_bytes()
            intent = {"schemaVersion": 1, "sourceSha": "a" * 40, "correlationId": correlation,
                      "scenario": "install", "jobId": "33333333-3333-4333-8333-333333333333",
                      "operationId": "44444444-4444-4444-8444-444444444444",
                      "bootSessionUuid": "55555555-5555-4555-8555-555555555555",
                      "reservationId": "env-1234", "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                      "serverInstanceId": ready["serverInstanceId"], "serverPid": os.getpid(),
                      "serverProcessStartIdentity": ready["serverProcessStartIdentity"],
                      "readySha256": hashlib.sha256(raw).hexdigest(), "stopRequestCount": 1,
                      "port": 53633}
            external = evidence / "outside.json"
            external.write_text(json.dumps(intent))
            external.chmod(0o600)
            stop_intent = evidence / "server-stop-intent.json"
            stop_intent.symlink_to(external)
            with self.assertRaises(ValueError):
                prepare_desktop_update_fixture.write_macos_graceful_exit(ready_file, raw)
            stop_intent.unlink()
            intent["serverPid"] += 1
            stop_intent.write_text(json.dumps(intent))
            stop_intent.chmod(0o600)
            with self.assertRaises(ValueError):
                prepare_desktop_update_fixture.write_macos_graceful_exit(ready_file, raw)
            intent["serverPid"] = os.getpid()
            intent["fixtureReceiptArtifactId"] = "sha256-" + "c" * 64
            stop_intent.write_text(json.dumps(intent))
            stop_intent.chmod(0o600)
            with self.assertRaises(ValueError):
                prepare_desktop_update_fixture.write_macos_graceful_exit(ready_file, raw)
            self.assertFalse((evidence / "server-stop.json").exists())

    @staticmethod
    def synthetic_windows_acl_receipt(path, *, private, establish=True):
        """Model the fixed protected stage and current-owner private children."""
        system, admins, recipient = "S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-4"
        is_directory = Path(path).is_dir()
        def entry(sid, rights, inheritance):
            return {"sid": sid, "rights": rights, "inheritance": inheritance,
                    "propagation": 0, "type": "Allow", "inherited": False}
        if private:
            inheritance = 3 if is_directory else 0
            acl = [entry(system, 0x1F01FF, inheritance),
                   entry(admins, 0x1F01FF, inheritance),
                   entry(recipient, 0x1F01FF, inheritance)]
        else:
            if not is_directory:
                raise ValueError("Synthetic fixture stage must be a directory")
            acl = [entry(system, 0x1F01FF, 3), entry(admins, 0x1F01FF, 3),
                   entry(recipient, 0x1200A9, 3)]
        return {"protected": True, "currentSid": recipient,
                "isDirectory": is_directory, "acl": acl}

    def setUp(self):
        # These tests create inert images with a fake Gradle executor. JVM
        # selection is exercised separately without starting a host build.
        jdk_patch = patch("prepare_desktop_update_fixture.require_jdk17")
        self.jdk_check = jdk_patch.start()
        self.addCleanup(jdk_patch.stop)
        tools_patch = patch("prepare_desktop_update_fixture.require_linux_build_tools", create=True)
        self.tools_check = tools_patch.start()
        self.addCleanup(tools_patch.stop)
        self.tools_patch = tools_patch
        acl_patch = patch("prepare_desktop_update_fixture.windows_acl_receipt",
                          side_effect=self.synthetic_windows_acl_receipt)
        self.acl_check = acl_patch.start()
        self.addCleanup(acl_patch.stop)

    @staticmethod
    def synthetic_server_paths(temporary):
        root = Path(temporary)
        if platform.system() == "Windows":
            stage_root = root / "mcp-update-fixture-a6285846-10e4-45c5-9cf7-b138a5beb222"
            directory = stage_root / "content"
            state = stage_root / "server-state"
            directory.mkdir(parents=True)
            state.mkdir()
            return directory, state / "ready.json"
        return root, root / "ready.json"

    def test_public_ready_phase_admits_only_expected_downloaded_update(self):
        # Public installed-DMG status observed during the native coordinator run.
        status = {"ok": True, "final": True, "data": {
            "phase": "ready", "availableVersion": "2.1.16"}}
        require_install_ready(status, "2.1.16")
        for phase in ("downloading", "installing", "failed", "ready_to_install"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                require_install_ready({**status, "data": {**status["data"], "phase": phase}}, "2.1.16")
        with self.assertRaises(ValueError):
            require_install_ready(status, "2.1.17")
        with self.assertRaises(ValueError):
            require_install_ready({**status, "ok": False}, "2.1.16")

    def test_proxy_arguments_derive_only_from_valid_server_ready_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready = Path(temporary) / "ready.json"
            ready.write_text(json.dumps({"port": 53633,
                "manifestSha256": "a" * 64}))
            self.assertEqual([
                "-Dhttps.proxyHost=127.0.0.1", "-Dhttps.proxyPort=53633",
                "-Dhttp.proxyHost=127.0.0.1", "-Dhttp.proxyPort=53633",
            ], fixture_proxy_arguments(ready))
            for value in ({}, {"port": 0, "manifestSha256": "a" * 64},
                          {"port": 53633, "manifestSha256": "bad"}):
                ready.write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    fixture_proxy_arguments(ready)

    def test_serve_ready_digest_binds_the_exact_manifest_response(self):
        """The native proxy admission receipt must name the bytes served for GET."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, ready_file = self.synthetic_server_paths(temporary)
            manifest = {"schemaVersion": 1, "assets": [{"fileName": "target.msi"}],
                        "buildNumber": 16800}
            fixture_receipt = directory / "fixture-receipt.json"
            fixture_receipt.write_text(json.dumps({
                "sourceFingerprint": "f" * 64, "manifest": manifest}))
            served_body = json.dumps(manifest, separators=(",", ":")).encode()

            class FakeServer:
                def __init__(self, address, handler):
                    self.server_address = ("127.0.0.1", 53633)

                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    return False

                def serve_forever(self):
                    ready = json.loads(ready_file.read_text())
                    if platform.system() == "Windows":
                        self_assert.assertEqual(directory.parent / "server-state", ready_file.parent)
                        self_assert.assertTrue((ready_file.parent / "probe-events").is_dir())
                        self_assert.assertFalse((directory / "probe-events").exists())
                    self_assert.assertEqual(hashlib.sha256(served_body).hexdigest(),
                                            ready.get("manifestSha256"))
                    self_assert.assertEqual("a6285846-10e4-45c5-9cf7-b138a5beb222",
                                            ready.get("serverInstanceId"))
                    self_assert.assertEqual("c" * 64, ready.get("peerCertificateSha256"))
                    self_assert.assertEqual(hashlib.sha256(fixture_receipt.read_bytes()).hexdigest(),
                                            ready.get("fixtureReceiptSha256"))
                    self_assert.assertEqual(1234, ready.get("serverPid"))
                    self_assert.assertEqual("darwin:100:123", ready.get("serverProcessStartIdentity"))
                    if os.name == "posix":
                        self_assert.assertEqual(0o600, ready_file.stat().st_mode & 0o777)
                    self_assert.assertEqual(["-Dhttps.proxyHost=127.0.0.1",
                                             "-Dhttps.proxyPort=53633",
                                             "-Dhttp.proxyHost=127.0.0.1",
                                             "-Dhttp.proxyPort=53633"],
                                            fixture_proxy_arguments(ready_file))

            self_assert = self
            with patch("prepare_desktop_update_fixture.require_fixture_certificate_current"), \
                    patch("prepare_desktop_update_fixture.load_resources", return_value=(manifest, {})), \
                    patch("prepare_desktop_update_fixture.probe_certificate_sha256", return_value="c" * 64), \
                    patch("prepare_desktop_update_fixture.server_process_identity",
                          return_value={"serverPid": 1234,
                                        "serverProcessStartIdentity": "darwin:100:123"}), \
                    patch("prepare_desktop_update_fixture.uuid.uuid4",
                          return_value=uuid.UUID("a6285846-10e4-45c5-9cf7-b138a5beb222")), \
                    patch("prepare_desktop_update_fixture.ssl.SSLContext"), \
                    patch("prepare_desktop_update_fixture.socketserver.ThreadingTCPServer", FakeServer):
                prepare_desktop_update_fixture.serve(
                    directory, directory / "server.pem", directory / "server.key", ready_file, True)

    def test_server_process_identity_uses_stable_native_creation_time(self):
        first = prepare_desktop_update_fixture.server_process_identity()
        second = prepare_desktop_update_fixture.server_process_identity()
        self.assertEqual(first, second)
        self.assertEqual(os.getpid(), first["serverPid"])
        self.assertTrue(first["serverProcessStartIdentity"].startswith(
            {"Linux": "linux:", "Darwin": "darwin:", "Windows": "windows:"}[platform.system()]))
        with patch("prepare_desktop_update_fixture.platform.system", return_value="unsupported"):
            with self.assertRaisesRegex(ValueError, "unsupported"):
                prepare_desktop_update_fixture.server_process_identity()

    def test_serve_refuses_changed_fixture_receipt_before_ready_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, ready_file = self.synthetic_server_paths(temporary)
            (directory / "fixture-receipt.json").write_text(json.dumps({
                "sourceFingerprint": "f" * 64, "manifest": {"assets": ["changed"]}}))
            with patch("prepare_desktop_update_fixture.require_fixture_certificate_current"), \
                    patch("prepare_desktop_update_fixture.load_resources",
                          return_value=({"assets": []}, {})), \
                    patch("prepare_desktop_update_fixture.probe_certificate_sha256",
                          return_value="c" * 64):
                with self.assertRaisesRegex(ValueError, "receipt changed"):
                    prepare_desktop_update_fixture.serve(
                        directory, directory / "server.pem", directory / "server.key", ready_file, True)
            self.assertFalse(ready_file.exists())

    def test_serve_refuses_same_manifest_receipt_swap_during_resource_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, ready_file = self.synthetic_server_paths(temporary)
            receipt = directory / "fixture-receipt.json"
            manifest = {"assets": []}
            receipt.write_text(json.dumps({"sourceFingerprint": "a" * 64,
                                           "manifest": manifest, "builds": ["A"]}))

            def swapped_resources(_directory, *, receipt_bytes):
                receipt.write_text(json.dumps({"sourceFingerprint": "a" * 64,
                                               "manifest": manifest, "builds": ["B"]}))
                return manifest, {}

            class NoListener:
                def __init__(self, *_):
                    raise AssertionError("swapped receipt reached listener")

            with patch("prepare_desktop_update_fixture.require_fixture_certificate_current"), \
                    patch("prepare_desktop_update_fixture.load_resources",
                          side_effect=swapped_resources), \
                    patch("prepare_desktop_update_fixture.probe_certificate_sha256",
                          return_value="c" * 64), \
                    patch("prepare_desktop_update_fixture.server_process_identity",
                          return_value={"serverPid": 1234,
                                        "serverProcessStartIdentity": "windows:123456789"}), \
                    patch("prepare_desktop_update_fixture.ssl.SSLContext"), \
                    patch("prepare_desktop_update_fixture.socketserver.ThreadingTCPServer", NoListener):
                with self.assertRaisesRegex(ValueError, "receipt changed"):
                    prepare_desktop_update_fixture.serve(
                        directory, directory / "server.pem", directory / "server.key", ready_file, True)
            self.assertFalse(ready_file.exists())

    def test_serve_refuses_certificate_swap_during_tls_chain_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, ready_file = self.synthetic_server_paths(temporary)
            manifest = {"assets": []}
            (directory / "fixture-receipt.json").write_text(json.dumps({
                "sourceFingerprint": "a" * 64, "manifest": manifest}))
            certificate = directory / "server.pem"
            def pem(value):
                return ("-----BEGIN CERTIFICATE-----\n" +
                        base64.b64encode(value).decode("ascii") +
                        "\n-----END CERTIFICATE-----\n")
            certificate.write_text(pem(b"first DER"))

            class ReplacingTls:
                def load_cert_chain(self, *_):
                    certificate.write_text(pem(b"second DER"))

            class NoListener:
                def __init__(self, *_):
                    raise AssertionError("swapped certificate reached listener")

            with patch("prepare_desktop_update_fixture.require_fixture_certificate_current"), \
                    patch("prepare_desktop_update_fixture.load_resources",
                          return_value=(manifest, {})), \
                    patch("prepare_desktop_update_fixture.server_process_identity",
                          return_value={"serverPid": 1234,
                                        "serverProcessStartIdentity": "windows:123456789"}), \
                    patch("prepare_desktop_update_fixture.ssl.SSLContext",
                          return_value=ReplacingTls()), \
                    patch("prepare_desktop_update_fixture.socketserver.ThreadingTCPServer", NoListener):
                with self.assertRaisesRegex(ValueError, "certificate changed"):
                    prepare_desktop_update_fixture.serve(
                        directory, certificate, directory / "server.key", ready_file, True)
            self.assertFalse(ready_file.exists())

    def test_windows_stage_and_private_child_acl_reject_extra_principals(self):
        system, admins, recipient = "S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-4"
        def entry(sid, rights, inheritance):
            return {"sid": sid, "rights": rights, "inheritance": inheritance,
                    "propagation": 0, "type": "Allow", "inherited": False}
        stage = {"protected": True, "currentSid": system, "isDirectory": True,
                 "acl": [entry(system, 0x1F01FF, 3), entry(admins, 0x1F01FF, 3),
                         entry(recipient, 0x1200A9, 3)]}
        private = {"protected": True, "currentSid": system, "isDirectory": False,
                   "acl": [entry(system, 0x1F01FF, 0), entry(admins, 0x1F01FF, 0)]}
        with patch("prepare_desktop_update_fixture.windows_acl_receipt", return_value=stage):
            prepare_desktop_update_fixture.require_windows_private_acl(
                Path("C:/fixture"), private=False, directory=True)
            with self.assertRaisesRegex(ValueError, "protection"):
                stage["protected"] = False
                prepare_desktop_update_fixture.require_windows_private_acl(
                    Path("C:/fixture"), private=False, directory=True)
        with patch("prepare_desktop_update_fixture.windows_acl_receipt", return_value=private):
            prepare_desktop_update_fixture.require_windows_private_acl(
                Path("C:/fixture/ready.json"), private=True, directory=False)
            private["acl"].append(entry("S-1-1-0", 0x1200A9, 0))
            with self.assertRaisesRegex(ValueError, "principals or rights"):
                prepare_desktop_update_fixture.require_windows_private_acl(
                    Path("C:/fixture/ready.json"), private=True, directory=False)

    def test_windows_serve_requires_live_stage_acl_before_fixture_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("prepare_desktop_update_fixture.platform.system", return_value="Windows"), \
                    patch("prepare_desktop_update_fixture.require_fixture_certificate_current"), \
                    patch("prepare_desktop_update_fixture.require_windows_private_acl",
                          side_effect=ValueError("unsafe Windows stage")), \
                    patch("prepare_desktop_update_fixture.load_resources",
                          side_effect=AssertionError("unsafe stage reached resources")):
                directory, ready_file = self.synthetic_server_paths(temporary)
                with self.assertRaisesRegex(ValueError, "unsafe Windows stage"):
                    prepare_desktop_update_fixture.serve(
                        directory, directory / "server.pem", directory / "server.key", ready_file, True)
            self.assertFalse(ready_file.exists())
            self.assertFalse((directory / "probe-events").exists())

    def test_windows_ready_publish_fails_closed_without_private_file_acl(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready_file = Path(temporary) / "ready.json"
            with patch("prepare_desktop_update_fixture.platform.system", return_value="Windows"), \
                    patch("prepare_desktop_update_fixture.require_windows_private_acl",
                          side_effect=ValueError("unsafe ready ACL")):
                with self.assertRaisesRegex(ValueError, "unsafe ready ACL"):
                    prepare_desktop_update_fixture.write_private_ready_json(
                        ready_file, {"port": 53633})
            self.assertFalse(ready_file.exists())
            self.assertEqual([], list(Path(temporary).iterdir()))

    def test_windows_ready_temp_is_private_before_receipt_bytes_are_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready_file = Path(temporary) / "ready.json"
            observed = []
            def inspect_acl_input(path, *, private, directory):
                self.assertTrue(private)
                self.assertFalse(directory)
                observed.append((Path(path).name, Path(path).read_bytes()))
            with patch("prepare_desktop_update_fixture.platform.system", return_value="Windows"), \
                    patch("prepare_desktop_update_fixture.require_windows_private_acl",
                          side_effect=inspect_acl_input):
                prepare_desktop_update_fixture.write_private_ready_json(
                    ready_file, {"port": 53633, "fixtureReceiptSha256": "a" * 64})
            self.assertEqual(b"", observed[0][1])
            self.assertEqual(2, len(observed))
            self.assertIn(b"fixtureReceiptSha256", observed[1][1])

    def test_synthetic_serve_cases_replay_windows_acl_admission(self):
        """Run the same fixture-server decisions under a Windows host branch."""
        with patch("prepare_desktop_update_fixture.platform.system", return_value="Windows"):
            self.test_serve_ready_digest_binds_the_exact_manifest_response()
            self.test_serve_refuses_changed_fixture_receipt_before_ready_publish()
            self.test_serve_refuses_same_manifest_receipt_swap_during_resource_admission()
            self.test_serve_refuses_certificate_swap_during_tls_chain_load()
            self.test_probe_event_requires_exact_manifest_get_and_is_immutable()

    def test_windows_server_state_requires_fresh_sibling_before_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("prepare_desktop_update_fixture.platform.system", return_value="Windows"), \
                    patch("prepare_desktop_update_fixture.require_fixture_certificate_current"), \
                    patch("prepare_desktop_update_fixture.load_resources",
                          side_effect=AssertionError("dirty state reached resources")):
                directory, ready_file = self.synthetic_server_paths(temporary)
                with self.assertRaisesRegex(ValueError, "protected sibling"):
                    prepare_desktop_update_fixture.serve(
                        directory, directory / "server.pem", directory / "server.key",
                        directory / "ready.json", True)
                (ready_file.parent / "stale-ready.json").write_text("old generation")
                with self.assertRaisesRegex(ValueError, "not fresh"):
                    prepare_desktop_update_fixture.serve(
                        directory, directory / "server.pem", directory / "server.key",
                        ready_file, True)
                self.assertFalse(ready_file.exists())

    def test_windows_server_rejects_process_other_than_stage_recipient(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("prepare_desktop_update_fixture.platform.system", return_value="Windows"), \
                    patch("prepare_desktop_update_fixture.require_fixture_certificate_current"), \
                    patch("prepare_desktop_update_fixture.load_resources",
                          side_effect=AssertionError("wrong user reached resources")):
                directory, ready_file = self.synthetic_server_paths(temporary)
                observations = []
                def wrong_owner(path, *, private, establish=True):
                    observations.append((Path(path), private, establish))
                    receipt = self.synthetic_windows_acl_receipt(path, private=private)
                    receipt["currentSid"] = "S-1-5-18"
                    if private:
                        receipt["acl"] = [item for item in receipt["acl"]
                                          if item["sid"] != "S-1-5-21-1-2-3-4"]
                    return receipt
                with patch("prepare_desktop_update_fixture.windows_acl_receipt",
                          side_effect=wrong_owner):
                    with self.assertRaisesRegex(ValueError, "recipient"):
                        prepare_desktop_update_fixture.serve(
                            directory, directory / "server.pem", directory / "server.key",
                            ready_file, True)
                self.assertIn((ready_file.parent, True, False), observations)
                self.assertFalse(ready_file.exists())

    def test_missing_selected_identity_is_rejected_before_runtime_start(self):
        # Native malformed-DMG preparation added a location but did not select it;
        # public ON then returned SELECT_LOCATION_FIRST without starting a runtime.
        status = {"ok": True, "final": True, "code": "OK", "data": {
            "selectedLocationId": None, "activeLocationId": None,
            "runtimeRunning": False,
        }}
        with self.assertRaises(ValueError):
            require_selected_location(status, "stable-fixture-location")
        selected = {**status, "data": {**status["data"],
            "selectedLocationId": "stable-fixture-location"}}
        require_selected_location(selected, "stable-fixture-location")
        with self.assertRaises(ValueError):
            require_active_runtime(selected, "stable-fixture-location")
        active = {**selected, "data": {**selected["data"],
            "activeLocationId": "stable-fixture-location", "runtimeRunning": True}}
        require_active_runtime(active, "stable-fixture-location")
        for changed in ("wrong-location", None):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                require_selected_location({**selected, "data": {**selected["data"],
                    "selectedLocationId": changed}}, "stable-fixture-location")

    def test_desktop_install_uses_owner_guard_without_android_interaction_flag(self):
        status = {"ok": True, "final": True, "controllerId": "observed-owner",
                  "configurationRevision": 9,
                  "data": {"phase": "ready", "availableVersion": "2.2.0"}}
        # The native macOS run rejected the Android-only switch before admission.
        self.assertEqual(["--json", "--controller-id", "observed-owner", "--if-revision", "9",
                          "updates", "install"], desktop_install_arguments(status, "2.2.0"))
        self.assertEqual(["--json", "--controller-id", "observed-owner", "--if-revision", "9",
                          "--async", "updates", "install"],
                         desktop_install_arguments(status, "2.2.0", asynchronous=True))
        for changes in ({"controllerId": None}, {"configurationRevision": True},
                        {"configurationRevision": -1}, {"final": False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                desktop_install_arguments({**status, **changes}, "2.2.0")

    def test_wrong_jvm_fails_before_creating_build_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, output, _ = self.prepared(Path(temporary))
            calls, runner = self.fake_gradle()
            self.jdk_check.side_effect = ValueError("Native fixture build requires JDK 17")
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "JDK 17"):
                    native_build(output, True, runner)
            self.assertFalse((output / "packages").exists())
            self.assertEqual([], calls)

    def test_missing_objcopy_fails_before_creating_build_output(self):
        # Fedora jlink failed late with Cannot run program "objcopy": error=2.
        # Reject the missing executable before consuming either immutable stage.
        self.tools_patch.stop()
        with tempfile.TemporaryDirectory() as temporary:
            _, _, output, _ = self.prepared(Path(temporary))
            calls, runner = self.fake_gradle()
            with patch("platform.system", return_value="Linux"), \
                    patch("platform.machine", return_value="x86_64"), \
                    patch("prepare_desktop_update_fixture.shutil.which", return_value=None):
                with self.assertRaisesRegex(ValueError, "objcopy.*binutils"):
                    native_build(output, True, runner)
            self.assertFalse((output / "packages").exists())
            self.assertFalse((output / "build-base").exists())
            self.assertEqual([], calls)

    def test_arch_admission_does_not_require_deb_or_rpm_tools(self):
        self.tools_patch.stop()
        with patch("prepare_desktop_update_fixture.shutil.which",
                   side_effect=lambda tool: "/usr/bin/objcopy" if tool == "objcopy" else None):
            prepare_desktop_update_fixture.require_linux_build_tools("arch")

    def test_missing_package_tools_fail_before_creating_build_output(self):
        # Fedora reached jpackage after compilation and rejected DEB because
        # packaging tools were absent. Each missing tool must fail admission.
        self.tools_patch.stop()
        for missing in ("dpkg-deb", "fakeroot", "rpmbuild"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                _, _, output, _ = self.prepared(Path(temporary))
                calls, runner = self.fake_gradle()
                with patch("platform.system", return_value="Linux"), \
                        patch("platform.machine", return_value="x86_64"), \
                        patch("prepare_desktop_update_fixture.shutil.which",
                              side_effect=lambda tool: None if tool == missing else "/usr/bin/" + tool):
                    with self.assertRaisesRegex(ValueError, missing):
                        native_build(output, True, runner)
                self.assertFalse((output / "packages").exists())
                self.assertFalse((output / "build-base").exists())
                self.assertEqual([], calls)

    def test_rejected_macos_packaging_jdk_fails_before_creating_build_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, output, _ = self.prepared(Path(temporary))
            plan_path = output / "build-plan.json"
            plan = json.loads(plan_path.read_text())
            plan["platform"] = "macos"
            plan_path.write_text(json.dumps(plan))
            identity = {key: plan["runtime"][key] for key in ("sha256", "sizeBytes")}
            def must_not_build(*args, **kwargs):
                self.fail("Rejected packaging JDK reached native build")
            with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="x86_64"), \
                    patch("prepare_desktop_update_fixture.runtime_identity", return_value=identity), \
                    patch.dict(os.environ, {"JAVA_HOME": temporary}), \
                    patch("prepare_desktop_update_fixture.require_macos_packaging_jdk", create=True,
                          side_effect=ValueError("Homebrew JDK is rejected")) as check:
                with self.assertRaisesRegex(ValueError, "Homebrew JDK"):
                    native_build(output, True, must_not_build)
                check.assert_called_once_with(Path(temporary), "x86_64")
            self.assertFalse((output / "packages").exists())
            self.assertFalse((output / "build-base").exists())

    def source(self, root):
        repository = root / "repo"
        repository.mkdir()
        subprocess.run(["git", "init", "--quiet", str(repository)], check=True, capture_output=True)
        (repository / "gradle.properties").write_text("vpnControlVersion=2.1.3\n")
        (repository / "gradlew").write_text("#!/bin/sh\nexit 99 # fixture, never executed\n")
        (repository / "gradlew").chmod(0o755)
        (repository / ".gitignore").write_text("build/\nignored-secret\n")
        (repository / "ignored-secret").write_text("not-a-source-input")
        (repository / "build").mkdir()
        (repository / "build/generated").write_text("ignored")
        (repository / "scripts").mkdir()
        (repository / "scripts/install_arch_desktop_update.sh").write_text("# inert fixture installer, never executed\n")
        runtime = root / "runtime"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62).to_bytes(2, "little")
        runtime.write_bytes(header + b"frozen-runtime-not-executed")
        return repository, runtime

    def prepared(self, root):
        repository, runtime = self.source(root)
        output = root / "fixture"
        plan = prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
        return repository, runtime, output, plan

    def make_image(self, image, version, changed=False, short_hash=False):
        jars = image / "lib/app"
        jars.mkdir(parents=True)
        (image / "bin").mkdir()
        (image / "bin/vpn-control").write_bytes(b"\x7fELFpublic-launcher-not-executed")
        (image / "bin/vpn-control").chmod(0o755)
        target = jars / "desktopApp.jar"
        with zipfile.ZipFile(target, "w") as jar:
            jar.writestr(MAIN_CLASS, b"different-executable" if changed else b"same-frozen-executable")
            jar.writestr(VERSION_RESOURCE, f"displayVersion={version}\nbuildNumber={version_build(version)}\n")
            jar.writestr("linux-install-user.sh", "fixed-captured-worker")
        if short_hash:
            # Compose formats each MD5 byte without zero padding. Keep the ZIP
            # contents identical while deterministically obtaining such a name.
            for attempt in range(1024):
                with zipfile.ZipFile(target, "a") as jar:
                    jar.comment = str(attempt).encode()
                digest = hashlib.md5(target.read_bytes()).digest()
                suffix = "".join(format(value, "x") for value in digest)
                if len(suffix) < 32:
                    break
            self.assertLess(len(suffix), 32)
        else:
            suffix = hashlib.md5(target.read_bytes()).hexdigest()
        name = "desktopApp-" + suffix + ".jar"
        target.rename(jars / name)
        (jars / "vpn-control.cfg").write_text("[Application]\napp.classpath=$APPDIR/" + name +
            "\napp.mainclass=com.kardinal.vpncontrol.desktop.MainKt\n")
        return image

    def fake_gradle(self, changed_target=False):
        calls = []

        def run(command, *, cwd, stdout, stderr, check):
            calls.append((command, cwd))
            version = next(value.split("=", 1)[1] for value in command if value.startswith("-PvpnControlVersion="))
            root = cwd / "desktopApp/build/compose/binaries/main"
            self.make_image(root / "app/vpn-control", version, changed=changed_target and version == "2.1.3")
            for extension in ("deb", "rpm"):
                destination = root / extension
                destination.mkdir()
                (destination / ("vpn-control-" + version + "." + extension)).write_bytes(b"synthetic-" + extension.encode())
            stdout.write(b"synthetic Gradle fixture; no native package was built\n")
            return subprocess.CompletedProcess(command, 0)

        return calls, run

    def test_base20_versions_remain_exact_and_monotonic(self):
        self.assertEqual(16460, version_build("2.1.3"))
        self.assertEqual(version_build("2.0.19") + 20, version_build("2.1.0"))
        for invalid in ("0.1.1", "1.20.0", "20.0.0", "01.0.0", "1.01.0", "1.0", "1.0.0-extra"):
            with self.assertRaises(ValueError):
                version_build(invalid)

    def test_snapshot_keeps_dirty_and_untracked_source_but_no_ignored_data_or_source_edits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime, output, plan = self.prepared(root)
            snapshot = json.loads((output / "snapshot.json").read_text())
            self.assertEqual("2.1.3", snapshot["canonicalVersion"])
            self.assertEqual("vpnControlVersion=2.1.3\n", (repository / "gradle.properties").read_text())
            self.assertEqual({".gitignore", "gradle.properties", "gradlew", "scripts/install_arch_desktop_update.sh"},
                             {entry["path"] for entry in snapshot["files"]})
            self.assertFalse((output / "source/ignored-secret").exists())
            self.assertEqual(file_hash(runtime), plan["runtime"]["sha256"])
            self.assertEqual(["2.1.2", "2.1.3"], [stage["version"] for stage in plan["stages"]])
            for stage in plan["stages"]:
                self.assertIn("-PvpnControlVersion=" + stage["version"], stage["command"])
            self.assertEqual(0, (output / "source/gradle.properties").stat().st_mode & 0o222)
            verify_sources(output / "source", snapshot["files"])

    def test_prepare_rejects_missing_git_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            output = root / "fixture"
            with patch.dict(os.environ, {"PATH": ""}), \
                    self.assertRaisesRegex(ValueError, "requires git on PATH"):
                prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            self.assertFalse(output.exists())

    def test_prepare_rejects_source_archive_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            archive = root / "source-archive"
            shutil.copytree(repository, archive, ignore=shutil.ignore_patterns(".git"))
            output = root / "fixture"
            with self.assertRaisesRegex(ValueError, "requires a Git working tree"):
                prepare(archive, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            self.assertFalse(output.exists())

    def test_prepare_rejects_git_worktree_subdirectory_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            output = root / "fixture"
            with self.assertRaisesRegex(ValueError, "working tree root"):
                prepare(repository / "scripts", output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            self.assertFalse(output.exists())

    def test_rejects_generated_android_native_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _ = self.source(Path(temporary))
            cache = repository / "app/.cxx/build-state.json"
            cache.parent.mkdir(parents=True)
            cache.write_text("generated native cache")
            with self.assertRaisesRegex(ValueError, "Generated"):
                source_entries(repository)

    def test_rejects_generated_tracked_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _ = self.source(root)
            (repository / ".gitignore").write_text("")
            with self.assertRaisesRegex(ValueError, "Generated"):
                source_entries(repository)

    def test_rejects_external_symlink_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if not symlink_probe_available(root):
                self.skipTest("ordinary user cannot create fixture symlinks")
            repository, runtime = self.source(root)
            (repository / "escape").symlink_to(runtime)
            with self.assertRaisesRegex(ValueError, "escapes"):
                source_entries(repository)

    def test_excluded_gitlink_records_pin_and_empty_uninitialized_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            pin = "d09182614c7778c1e0f51d990635c5d4249c437e"
            subprocess.run(["git", "-C", str(repository), "update-index", "--add", "--cacheinfo",
                            "160000," + pin + ",native-source"], check=True, capture_output=True)
            (repository / "native-source").mkdir()
            output = root / "fixture"
            prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            snapshot = json.loads((output / "snapshot.json").read_text())
            entry = next(value for value in snapshot["files"] if value["path"] == "native-source")
            self.assertEqual(pin, entry["gitlink"]["indexCommit"])
            self.assertFalse(entry["gitlink"]["initialized"])
            self.assertIsNone(entry["gitlink"]["headCommit"])
            self.assertIsNone(entry["gitlink"]["dirty"])
            self.assertTrue(entry["excludedFromBuild"])
            self.assertFalse((output / "source/native-source").exists())
            verify_sources(output / "source", snapshot["files"])

    def test_excluded_initialized_gitlink_records_dirty_content_without_copying_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _ = self.source(root)
            submodule = repository / "native-source"
            subprocess.run(["git", "init", "--quiet", str(submodule)], check=True, capture_output=True)
            (submodule / "runtime.go").write_text("committed source\n")
            subprocess.run(["git", "-C", str(submodule), "add", "runtime.go"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(submodule), "-c", "user.name=Fixture", "-c",
                            "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture"],
                           check=True, capture_output=True)
            pin = subprocess.run(["git", "-C", str(submodule), "rev-parse", "HEAD"],
                                 check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "-C", str(repository), "update-index", "--add", "--cacheinfo",
                            "160000," + pin + ",native-source"], check=True, capture_output=True)
            def captured():
                return next(value["gitlink"] for value in source_entries(repository)
                            if value["path"] == "native-source")
            clean = captured()
            self.assertEqual(pin, clean["headCommit"])
            self.assertFalse(clean["dirty"])
            (submodule / "runtime.go").write_text("first dirty source\n")
            first = captured()
            self.assertTrue(first["dirty"])
            (submodule / "runtime.go").write_text("second dirty source\n")
            second = captured()
            self.assertNotEqual(first["workingTreeFingerprint"], second["workingTreeFingerprint"])
            self.assertEqual(pin, second["indexCommit"])

    def test_runtime_architecture_is_checked_from_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, runtime = self.source(root)
            self.assertEqual(runtime.stat().st_size, runtime_identity(runtime, "linux", "x86_64")["sizeBytes"])
            with self.assertRaisesRegex(ValueError, "architecture"):
                runtime_identity(runtime, "linux", "arm64")
            runtime.write_bytes(b"not an ELF")
            with self.assertRaisesRegex(ValueError, "ELF"):
                runtime_identity(runtime, "linux", "x86_64")

    def test_real_compose_unpadded_digest_names_preserve_code_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self.make_image(root / "base", "2.1.2")
            target = self.make_image(root / "target", "2.1.3", short_hash=True)
            self.assertEqual(image_identity(base, "2.1.2")["codeFingerprint"],
                             image_identity(target, "2.1.3")["codeFingerprint"])

    def test_installed_image_rejects_a_stale_unlisted_main_jar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = self.make_image(root / "installed", "2.3.1")
            stale = self.make_image(root / "old-fixture", "1.0.0")
            stale_main = None
            for path in (stale / "lib/app").glob("*.jar"):
                with zipfile.ZipFile(path) as jar:
                    if MAIN_CLASS in jar.namelist():
                        stale_main = path
                        break
            self.assertIsNotNone(stale_main)
            extra = image / "lib/app/stale-main.jar"
            extra.write_bytes(stale_main.read_bytes())
            with self.assertRaisesRegex(ValueError, "Packaged version resource disagrees"):
                image_identity(image, "2.3.1")
            extra.unlink()
            self.assertTrue(image_identity(image, "2.3.1")["codeFingerprint"])

    def test_installed_image_rejects_unlisted_legacy_dependency_jar(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = self.make_image(Path(temporary) / "installed", "2.3.1")
            extra = image / "lib/app/old-core-desktop.jar"
            with zipfile.ZipFile(extra, "w") as jar:
                jar.writestr("example/Legacy.class", b"old dependency")
            with self.assertRaisesRegex(ValueError, "classpath must reference every JAR exactly once"):
                image_identity(image, "2.3.1")
            extra.unlink()
            self.assertTrue(image_identity(image, "2.3.1")["codeFingerprint"])

    def test_jpackage_repacked_jars_keep_logical_identity_after_filename_hash_was_chosen(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self.make_image(root / "base", "2.1.2")
            target = self.make_image(root / "target", "2.1.3")
            # macOS jpackage rewrites ZIP metadata after Compose chose names.
            # Every class/resource byte and the launcher's classpath stay intact.
            for index, image in enumerate((base, target)):
                path = next((image / "lib/app").glob("*.jar"))
                with zipfile.ZipFile(path, "a") as jar:
                    jar.comment = ("repacked-" + str(index)).encode()
            self.assertEqual(image_identity(base, "2.1.2")["codeFingerprint"],
                             image_identity(target, "2.1.3")["codeFingerprint"])

    def test_declared_classpath_order_and_membership_are_part_of_executable_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = self.make_image(Path(temporary) / "app", "2.1.3")
            app = image / "lib/app"
            dependency = app / "dependency.jar"
            with zipfile.ZipFile(dependency, "w") as jar:
                jar.writestr("example/Duplicate.class", b"dependency-priority")
            config = app / "vpn-control.cfg"
            original = config.read_text()
            entry = "app.classpath=$APPDIR/dependency.jar\n"
            config.write_text(original + entry)
            first = image_identity(image, "2.1.3")["codeFingerprint"]
            config.write_text(original.replace("[Application]\n", "[Application]\n" + entry))
            self.assertNotEqual(first, image_identity(image, "2.1.3")["codeFingerprint"])
            for invalid in (original, original + entry + entry, original + "app.classpath=$APPDIR/../dependency.jar\n"):
                config.write_text(invalid)
                with self.assertRaisesRegex(ValueError, "classpath"):
                    image_identity(image, "2.1.3")

    def test_native_build_requires_confirmation_before_reading_any_input(self):
        with self.assertRaisesRegex(ValueError, "confirmation"):
            native_build(Path("/never-read"), False)

    def test_build_cli_accepts_guest_or_native_host_confirmation(self):
        for confirmation in ("--confirm-owned-disposable-guest", "--confirm-owned-native-host-build"):
            with self.subTest(confirmation=confirmation), \
                    patch.object(sys, "argv", ["fixture", "build", "--directory", "fixture", confirmation]), \
                    patch("prepare_desktop_update_fixture.native_build", return_value={"ok": True}) as build, \
                    unittest.mock.patch("sys.stdout", new_callable=io.StringIO):
                prepare_desktop_update_fixture.main()
                build.assert_called_once_with(Path("fixture"), True, None, False)

    def test_native_host_build_confirmation_cannot_unlock_guest_only_actions(self):
        commands = (
            ["recover-macos-target-package", "--directory", "fixture"],
            ["authorize-macos-base-offload", "--directory", "fixture", "--host-backup-manifest", "base.json"],
            ["finalize-macos-target-package-recovery", "--directory", "fixture"],
            ["serve", "--directory", "fixture", "--certificate", "cert.pem", "--private-key", "key.pem",
             "--ready-file", "ready.json"],
        )
        for command in commands:
            with self.subTest(command=command[0]), \
                    patch.object(sys, "argv", ["fixture", *command, "--confirm-owned-native-host-build"]), \
                    patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    prepare_desktop_update_fixture.main()
            self.assertEqual(2, error.exception.code)

    def test_expired_certificate_refuses_serve_before_fixture_ready(self):
        """An expired public fixture certificate cannot advertise a usable server."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ready_file = directory / "ready.json"
            expired = {"notBefore": "Sep  1 00:00:00 2026 GMT",
                       "notAfter": "Sep  9 00:00:00 2026 GMT"}
            with patch("prepare_desktop_update_fixture.time.time",
                       return_value=ssl.cert_time_to_seconds("Sep 20 00:00:00 2026 GMT")), \
                    patch("prepare_desktop_update_fixture.ssl._ssl._test_decode_cert",
                          return_value=expired) as decode, \
                    patch("prepare_desktop_update_fixture.load_resources",
                          side_effect=AssertionError("expired certificate reached fixture resources")), \
                    patch("prepare_desktop_update_fixture.ssl.SSLContext",
                          side_effect=AssertionError("expired certificate reached TLS setup")):
                with self.assertRaisesRegex(ValueError, "expired"):
                    prepare_desktop_update_fixture.serve(
                        directory, directory / "server.pem", directory / "server.key", ready_file, True)
            decode.assert_called_once_with(str(directory / "server.pem"))
            self.assertFalse(ready_file.exists())

    def test_current_certificate_validity_window_is_accepted(self):
        certificate = {"notBefore": "Sep 19 00:00:00 2026 GMT",
                       "notAfter": "Oct  3 00:00:00 2026 GMT"}
        with patch("prepare_desktop_update_fixture.ssl._ssl._test_decode_cert",
                   return_value=certificate):
            prepare_desktop_update_fixture.require_fixture_certificate_current(
                "server.pem", now=ssl.cert_time_to_seconds("Sep 20 00:00:00 2026 GMT"))

    def test_not_yet_valid_certificate_is_rejected_deterministically(self):
        certificate = {"notBefore": "Sep 21 00:00:00 2026 GMT",
                       "notAfter": "Oct 21 00:00:00 2026 GMT"}
        with patch("prepare_desktop_update_fixture.ssl._ssl._test_decode_cert",
                   return_value=certificate):
            with self.assertRaisesRegex(ValueError, "not yet valid"):
                prepare_desktop_update_fixture.require_fixture_certificate_current(
                    "server.pem", now=ssl.cert_time_to_seconds("Sep 20 00:00:00 2026 GMT"))

    def test_certificate_admission_explains_when_stdlib_decoder_is_unavailable(self):
        with patch.object(ssl, "_ssl", None):
            with self.assertRaisesRegex(ValueError, "inspection is unavailable"):
                prepare_desktop_update_fixture.require_fixture_certificate_current("server.pem")

    @unittest.skipUnless(os.name == "posix", "Physical Linux tar fixture requires POSIX file modes")
    def test_two_property_builds_capture_equal_code_and_original_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _, output, _ = self.prepared(root)
            calls, runner = self.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                receipt = native_build(output, True, runner)
            self.assertEqual(2, len(calls))
            # Default fixture builds retain their generated trees for diagnosis;
            # this was the storage accumulation that the explicit opt-in fixes.
            self.assertTrue((output / "build-base").is_dir())
            self.assertTrue((output / "build-target").is_dir())
            for _, checkout in calls:
                self.assertEqual("vpnControlVersion=2.1.3\n", (checkout / "gradle.properties").read_text())
            self.assertEqual("vpnControlVersion=2.1.3\n", (repository / "gradle.properties").read_text())
            base, target = receipt["builds"]
            self.assertEqual(base["codeFingerprint"], target["codeFingerprint"])
            self.assertNotEqual(base["mainJarSha256"], target["mainJarSha256"])
            manifest, resources = load_resources(output)
            self.assertEqual(16460, manifest["buildNumber"])
            self.assertEqual({"deb", "rpm", "arch-bundle"}, {asset["packageType"] for asset in manifest["assets"]})
            self.assertTrue(all(path.is_file() and not path.stat().st_mode & 0o222 for path in resources.values()))
            arch = next(asset for asset in manifest["assets"] if asset["packageType"] == "arch-bundle")
            with tarfile.open(resources[arch["fileName"]]) as archive:
                self.assertEqual(b"2.1.3\n", archive.extractfile("vpn-control-arch-update/VERSION").read())
                self.assertEqual(b"# inert fixture installer, never executed\n",
                                 archive.extractfile("vpn-control-arch-update/install.sh").read())
                self.assertTrue(archive.getmember("vpn-control-arch-update/app/bin/vpn-control").mode & 0o111)
            asset = manifest["assets"][0]
            path = resources[asset["fileName"]]
            path.chmod(0o600)
            path.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "changed"):
                load_resources(output)

    @unittest.skipIf(os.name == "nt", "Linux timing publication is covered on POSIX hosts")
    def test_opt_in_linux_timing_records_phases_without_changing_packages(self):
        from build_phase_timing import PhaseRecorder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = []
            recorder = None
            for label in ("plain", "timed"):
                branch = root / label
                branch.mkdir()
                _, _, output, _ = self.prepared(branch)
                snapshot = json.loads((output / "snapshot.json").read_text())
                snapshot["sourceHead"] = "a" * 40
                (output / "snapshot.json").write_text(json.dumps(snapshot))
                _, runner = self.fake_gradle()
                if label == "timed":
                    recorder = PhaseRecorder(root / ".rag_index/build-timings", "a" * 40,
                        "linux-fixture", "12345678-1234-4234-9234-123456789abc", "linux-builder")
                with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
                     patch("prepare_desktop_update_fixture.time.monotonic_ns", return_value=1_000_000_000):
                    receipt = native_build(output, True, runner, timing_recorder=recorder if label == "timed" else None)
                assets = {asset["packageType"]: asset["sha256"]
                          for stage in receipt["builds"] for asset in stage["assets"]
                          if asset["packageType"] in {"deb", "rpm"}}
                outputs.append((receipt, assets))
            self.assertEqual(outputs[0][1], outputs[1][1])
            self.assertEqual(outputs[0][0]["builds"][0]["codeFingerprint"],
                             outputs[1][0]["builds"][0]["codeFingerprint"])
            self.assertEqual(6, len(recorder.references))
            phases = [json.loads((root / item["path"]).read_text())["phase"]
                      for item in recorder.references]
            self.assertEqual(2, phases.count("runtime-prep"))
            self.assertEqual(2, phases.count("gradle"))
            self.assertEqual(2, phases.count("packaging"))

    @unittest.skipIf(os.name == "nt", "Linux timing publication is covered on POSIX hosts")
    def test_opt_in_timing_includes_native_helper_preparation(self):
        from build_phase_timing import PhaseRecorder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, _ = self.prepared(root)
            snapshot = json.loads((output / "snapshot.json").read_text())
            snapshot["sourceHead"] = "a" * 40
            (output / "snapshot.json").write_text(json.dumps(snapshot))
            plan = json.loads((output / "build-plan.json").read_text())
            plan["stages"][0]["preparation"] = [["bash", "./scripts/fixed-helper.sh"]]
            (output / "build-plan.json").write_text(json.dumps(plan))
            recorder = PhaseRecorder(root / ".rag_index/build-timings", "a" * 40,
                "linux-fixture", "12345678-1234-4234-9234-123456789abc", "linux-builder")
            _, gradle = self.fake_gradle()
            helpers = []
            def runner(command, **kwargs):
                if command == ["bash", "./scripts/fixed-helper.sh"]:
                    helpers.append(command)
                    return subprocess.CompletedProcess(command, 0)
                return gradle(command, **kwargs)
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
                 patch("prepare_desktop_update_fixture.time.monotonic_ns", return_value=1_000_000_000):
                native_build(output, True, runner, timing_recorder=recorder)
            self.assertEqual(1, len(helpers))
            receipts = [json.loads((root / item["path"]).read_text())
                        for item in recorder.references]
            self.assertEqual(7, len(receipts))
            self.assertEqual(3, sum(item["phase"] == "runtime-prep" for item in receipts))
            self.assertTrue(any("runtime-prep-base-preparation" in item["path"]
                                for item in recorder.references))

    def test_native_stage_uses_only_frozen_runtime_when_ignored_linux_binary_exists(self):
        """An ignored host runtime cannot enter a same-source fixture stage."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            ignored = repository / "desktopApp/src/main/resources/bin/linux-amd64/sing-box"
            foreign_ignored = repository / "desktopApp/src/main/resources/bin/darwin-arm64/sing-box"
            ignored.parent.mkdir(parents=True)
            ignored.write_bytes(b"ignored-host-linux-runtime")
            foreign_ignored.parent.mkdir(parents=True)
            foreign_ignored.write_bytes(b"ignored-host-darwin-runtime")
            with (repository / ".gitignore").open("a") as rules:
                rules.write("desktopApp/src/main/resources/bin/\n")
            output = root / "fixture"
            prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            expected_runtime = file_hash(runtime)
            _, fake = self.fake_gradle()

            def runner(command, *, cwd, stdout, stderr, check):
                bundled = cwd / "desktopApp/src/main/resources/bin/linux-amd64/sing-box"
                self.assertTrue(bundled.is_file())
                self.assertEqual(expected_runtime, file_hash(bundled))
                self.assertNotEqual(file_hash(ignored), file_hash(bundled))
                self.assertFalse((cwd / "desktopApp/src/main/resources/bin/darwin-arm64/sing-box").exists())
                return fake(command, cwd=cwd, stdout=stdout, stderr=stderr, check=check)

            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                native_build(output, True, runner)

    def test_native_stage_excludes_stale_desktop_build_output_before_fake_gradle_runs(self):
        """A host class/resource tree cannot be reused by either isolated stage."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            stale_class = repository / "desktopApp/build/classes/kotlin/main/Stale.class"
            stale_resource = repository / "desktopApp/build/resources/main/bin/linux-amd64/sing-box"
            stale_class.parent.mkdir(parents=True)
            stale_resource.parent.mkdir(parents=True)
            stale_class.write_bytes(b"stale-host-class")
            stale_resource.write_bytes(b"stale-host-resource")
            output = root / "fixture"
            prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            _, fake = self.fake_gradle()

            def runner(command, *, cwd, stdout, stderr, check):
                self.assertFalse((cwd / "desktopApp/build").exists())
                return fake(command, cwd=cwd, stdout=stdout, stderr=stderr, check=check)

            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                native_build(output, True, runner)

    def test_windows_build_resolves_wrapper_to_its_own_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            (repository / "gradlew.bat").write_text("@exit /b 99\r\n")  # Never executed by this test.
            header = bytearray(256)
            header[:2] = b"MZ"
            header[0x3c:0x40] = (128).to_bytes(4, "little")
            header[128:132] = b"PE\0\0"
            header[132:134] = (0x8664).to_bytes(2, "little")
            runtime.write_bytes(header)
            output = root / "fixture"
            prepare(repository, output, "2.1.2", "2.1.3", runtime, "windows", "x86_64")
            calls = []

            def run(command, *, cwd, stdout, stderr, check):
                # Windows CreateProcess resolves a bare executable against the caller's
                # working directory/PATH, rather than the subprocess cwd parameter.
                self.assertEqual(str(cwd / "gradlew.bat"), command[0])
                self.assertTrue(Path(command[0]).is_file())
                calls.append(cwd)
                version = next(value.split("=", 1)[1] for value in command if value.startswith("-PvpnControlVersion="))
                binaries = cwd / "desktopApp/build/compose/binaries/main"
                self.make_image(binaries / "app/vpn-control", version)
                (binaries / "msi").mkdir()
                (binaries / "msi" / ("vpn-control-" + version + ".msi")).write_bytes(b"synthetic-msi-not-executed")
                return subprocess.CompletedProcess(command, 0)

            with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="AMD64"):
                receipt = native_build(output, True, run)
            self.assertEqual([output.resolve() / "build-base", output.resolve() / "build-target"], calls)
            self.assertEqual(receipt["builds"][0]["codeFingerprint"], receipt["builds"][1]["codeFingerprint"])

    def test_changed_target_code_never_receives_same_source_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, _ = self.prepared(root)
            _, runner = self.fake_gradle(changed_target=True)
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "executable content differ"):
                    native_build(output, True, runner, discard_completed_builds=True)
            # The completed base may be reclaimed, but a target rejected by the
            # same-source comparison remains available for diagnosis.
            self.assertFalse((output / "build-base").exists())
            self.assertTrue((output / "build-target").is_dir())
            self.assertFalse((output / "fixture-receipt.json").exists())

    def test_opt_in_discards_only_completed_generated_build_trees_after_verified_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, _ = self.prepared(root)
            _, runner = self.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                receipt = native_build(output, True, runner, discard_completed_builds=True)
            self.assertFalse((output / "build-base").exists())
            self.assertFalse((output / "build-target").exists())
            for label, record in zip(("base", "target"), receipt["builds"]):
                evidence = json.loads((output / ("completed-" + label + ".json")).read_text())
                self.assertEqual({"schemaVersion": 1, "record": record}, evidence)
                self.assertTrue((output / record["image"]).is_dir())
            self.assertTrue((output / "source").is_dir())
            self.assertTrue((output / "packages/base").is_dir())
            self.assertTrue((output / "packages/target").is_dir())

    def test_opt_in_retains_failed_target_build_tree_and_never_writes_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, _ = self.prepared(root)
            _, successful = self.fake_gradle()

            def fail_target(command, **kwargs):
                result = successful(command, **kwargs)
                if any(value == "-PvpnControlVersion=2.1.3" for value in command):
                    return subprocess.CompletedProcess(command, 1)
                return result

            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "Native build failed"):
                    native_build(output, True, fail_target, discard_completed_builds=True)
            self.assertFalse((output / "build-base").exists())
            self.assertTrue((output / "build-target").is_dir())
            self.assertTrue((output / "completed-base.json").is_file())
            self.assertFalse((output / "completed-target.json").exists())
            self.assertFalse((output / "fixture-receipt.json").exists())

    def test_macos_target_package_recovery_requires_verified_base_then_uses_packaged_task_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, plan = self.prepared(root)
            plan["platform"] = "macos"
            plan["stages"][1]["command"] = ["./gradlew", "--no-daemon", "-PvpnControlVersion=2.1.3",
                                               ":desktopApp:createDistributable", ":desktopApp:packageDmg"]
            (output / "build-plan.json").write_text(json.dumps(plan))
            base, target = plan["stages"]
            base_output = output / "packages/base"
            base_image = base_output / "vpn-control.app"
            self.make_image(base_image, base["version"])
            (base_image / "Contents").mkdir(exist_ok=True)
            (base_image / "lib/app").rename(base_image / "Contents/app")
            (base_image / "lib").rmdir()
            base_dmg = base_output / "vpn-control-2.1.2.dmg"
            base_dmg.write_bytes(b"base-dmg")
            base_dmg.chmod(0o400)
            base_identity = image_identity(base_image, base["version"])
            base_record = {**base, **base_identity, "image": "packages/base/vpn-control.app",
                           "assets": [package_asset(base_dmg, "macos", "x86_64", base["version"])],
                           "sourceFingerprint": plan["sourceFingerprint"]}
            (base_output / "TEST-ONLY-INSTALL-FIXTURE.json").write_text(json.dumps({
                "testOnly": True, "productionTrustChanged": False, "sameSourceBuild": True,
                "version": base["version"], **base_identity, "sourceFingerprint": plan["sourceFingerprint"]}))
            (output / "completed-base.json").write_text(json.dumps({"schemaVersion": 1, "record": base_record}))
            checkout = output / "build-target"
            shutil.copytree(output / "source", checkout)
            checkout.chmod(0o700)
            (checkout / "desktopApp").mkdir()
            for path in checkout.rglob("*"):
                if path.is_dir() and not path.is_symlink():
                    path.chmod(0o700)
            image = checkout / "desktopApp/build/compose/binaries/main/app/vpn-control.app"
            self.make_image(image, target["version"])
            (image / "Contents").mkdir(exist_ok=True)
            (image / "lib/app").rename(image / "Contents/app")
            (image / "lib").rmdir()
            calls = []
            def package(command, *, cwd, stdout, stderr, check):
                calls.append(command)
                dmg = cwd / "desktopApp/build/compose/binaries/main/dmg/vpn-control-2.1.3.dmg"
                dmg.parent.mkdir(parents=True, exist_ok=True)
                dmg.write_bytes(b"target-dmg")
                return subprocess.CompletedProcess(command, 0)
            identity = {key: plan["runtime"][key] for key in ("sha256", "sizeBytes")}
            with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="x86_64"), \
                    patch("prepare_desktop_update_fixture.runtime_identity", return_value=identity), \
                    patch.dict(os.environ, {"JAVA_HOME": temporary}), \
                    patch("prepare_desktop_update_fixture.require_macos_packaging_jdk"):
                stale = checkout / "desktopApp/build/compose/binaries/main/dmg/stale.dmg"
                stale.parent.mkdir(parents=True)
                stale.write_bytes(b"stale-output")
                with self.assertRaisesRegex(ValueError, "stale native dmg"):
                    recover_macos_target_package(output, True,
                                                 lambda *args, **kwargs: self.fail("stale package must not run"))
                stale.unlink()
                receipt = recover_macos_target_package(output, True, package)
                (output / "fixture-receipt.json").unlink()
                with self.assertRaisesRegex(ValueError, "terminal target result"):
                    recover_macos_target_package(output, True,
                                                 lambda *args, **kwargs: self.fail("completed target must not run"))
                (output / "fixture-receipt.json").write_text(json.dumps(receipt))
                (output / "completed-target.json").unlink()
                with self.assertRaisesRegex(ValueError, "terminal target result"):
                    recover_macos_target_package(output, True,
                                                 lambda *args, **kwargs: self.fail("receipt target must not run"))
            self.assertEqual(":desktopApp:packageDmg", calls[0][-1])
            self.assertNotIn(":desktopApp:createDistributable", calls[0])
            self.assertEqual(base_record["codeFingerprint"], receipt["builds"][1]["codeFingerprint"])
            self.assertTrue((output / "fixture-receipt.json").is_file())

    def test_macos_target_package_recovery_rejects_missing_base_completion_before_running(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, output, plan = self.prepared(Path(temporary))
            plan["platform"] = "macos"
            (output / "build-plan.json").write_text(json.dumps(plan))
            identity = {key: plan["runtime"][key] for key in ("sha256", "sizeBytes")}
            with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="x86_64"), \
                    patch("prepare_desktop_update_fixture.runtime_identity", return_value=identity):
                with self.assertRaisesRegex(ValueError, "Completed stage evidence"):
                    recover_macos_target_package(output, True, lambda *args, **kwargs: self.fail("must not package"))

    def test_offloaded_base_requires_durable_record_bound_to_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {"label": "base", "directory": "build-base", "version": "2.1.2", "buildNumber": 16440}
            plan = {"stages": [record, {"label": "target"}]}
            (root / "base-offload.json").write_text(json.dumps({"schemaVersion": 1, "record": {
                "schemaVersion": 1, "baseRecord": record, "hostBackupSha256": "a" * 64}}))
            with patch("prepare_desktop_update_fixture.completed_stage_record", return_value=record):
                self.assertEqual(record, verified_offloaded_base_record(root, plan))
            (root / "base-offload.json").write_text(json.dumps({"schemaVersion": 1, "record": {
                "schemaVersion": 1, "baseRecord": {**record, "version": "2.1.3"}, "hostBackupSha256": "a" * 64}}))
            with patch("prepare_desktop_update_fixture.completed_stage_record", return_value=record):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    verified_offloaded_base_record(root, plan)

    def test_cleanup_path_defense_rejects_noncanonical_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, plan = self.prepared(root)
            plan["stages"][0]["directory"] = "source"
            (output / "build-plan.json").unlink()
            (output / "build-plan.json").write_text(json.dumps(plan))
            calls, runner = self.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "Unexpected generated stage directory"):
                    native_build(output, True, runner, discard_completed_builds=True)
            self.assertEqual([], calls)
            self.assertTrue((output / "source").is_dir())

    def test_cleanup_path_defense_rejects_stage_symlink_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, plan = self.prepared(root)
            protected = output / "source"
            checkout = output / "build-base"
            try:
                checkout.symlink_to(protected, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest("ordinary user cannot create directory symlinks: " + str(error))
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                discard_completed_stage_directory(output.resolve(), plan["stages"][0])
            self.assertTrue(protected.is_dir())
            self.assertTrue(checkout.is_symlink())

    def test_frozen_source_tampering_or_architecture_mismatch_never_builds(self):
        for wrong_arch in (True, False):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, output, _ = self.prepared(root)
                if not wrong_arch:
                    source = output / "source/gradle.properties"
                    source.chmod(0o600)
                    source.write_text("changed-source")
                calls, runner = self.fake_gradle()
                with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="arm64" if wrong_arch else "x86_64"):
                    with self.assertRaises(ValueError):
                        native_build(output, True, runner)
                self.assertEqual([], calls)

    def test_resource_selector_keeps_exact_production_hosts_paths_and_methods(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "fixture.deb"
            package.write_bytes(b"abc")
            asset = package_asset(package, "linux", "x86_64", "2.1.3")
            manifest = {"assets": [asset]}
            path = asset["downloadUrl"].removeprefix("https://github.com")
            self.assertEqual("manifest", select_resource("GET", MANIFEST_PATH, "github.com", manifest))
            self.assertEqual("fixture.deb", select_resource("GET", path, "github.com:443", manifest))
            for method, target, host in (("POST", path, "github.com"), ("GET", "/", "github.com"),
                                         ("GET", path, "github.com.evil.invalid"),
                                         ("GET", path + "?anything", "github.com")):
                self.assertIsNone(select_resource(method, target, host, manifest))
            self.assertEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", asset["sha256"])

    def test_canonical_fixture_response_preserves_body_lengths_and_rejects_mutated_packages(self):
        class CapturedConnection:
            def __init__(self):
                self.data = bytearray()

            def sendall(self, value):
                self.data.extend(value)

        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "fixture.deb"
            package_bytes = b"fixture package bytes\x00with a non-text tail"
            package.write_bytes(package_bytes)
            asset = package_asset(package, "linux", "x86_64", "2.1.3")
            manifest = {"assets": [asset]}
            manifest_body = json.dumps(manifest, separators=(",", ":")).encode()

            manifest_response = CapturedConnection()
            self.assertEqual(len(manifest_body), write_resource_response(
                manifest_response, "manifest", manifest, {asset["fileName"]: package}, manifest_body))
            manifest_headers, manifest_sent_body = bytes(manifest_response.data).split(b"\r\n\r\n", 1)
            self.assertIn(b"Content-Length: " + str(len(manifest_body)).encode(), manifest_headers)
            self.assertEqual(manifest_body, manifest_sent_body)

            package_response = CapturedConnection()
            self.assertEqual(len(package_bytes), write_resource_response(
                package_response, asset["fileName"], manifest, {asset["fileName"]: package}, manifest_body))
            package_headers, package_sent_body = bytes(package_response.data).split(b"\r\n\r\n", 1)
            self.assertIn(b"Content-Length: " + str(len(package_bytes)).encode(), package_headers)
            self.assertEqual(package_bytes, package_sent_body)

            # A writer that reads a changed file after computing Content-Length
            # would produce a truncated or mismatched response. The canonical
            # writer rechecks both immutable identity values before writing.
            package.write_bytes(package_bytes + b" changed")
            with self.assertRaisesRegex(ValueError, "Frozen package changed"):
                write_resource_response(CapturedConnection(), asset["fileName"], manifest,
                                        {asset["fileName"]: package}, manifest_body)
            package.write_bytes(package_bytes)
            changed_asset = {**asset, "sizeBytes": len(package_bytes) + 1}
            with self.assertRaisesRegex(ValueError, "Frozen package length changed"):
                write_resource_response(CapturedConnection(), asset["fileName"], {"assets": [changed_asset]},
                                        {asset["fileName"]: package}, manifest_body)

    def test_canonical_fixture_failure_diagnostics_bound_each_https_stage(self):
        """The actual server path names its failed stage without logging request data."""
        connect = b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"

        class Connection:
            def __init__(self, chunks):
                self.chunks = iter(chunks)
                self.sent = bytearray()
                self.closed = 0

            def settimeout(self, value):
                self.timeout = value

            def recv(self, size):
                return next(self.chunks, b"")

            def sendall(self, value):
                self.sent.extend(value)

            def close(self):
                self.closed += 1

        class HandshakeFailure:
            def wrap_socket(self, request, server_side):
                raise ssl.SSLError("private fixture detail must not be logged")

        class TunnelingTls:
            def __init__(self, tunneled):
                self.tunneled = tunneled

            def wrap_socket(self, request, server_side):
                return self.tunneled

        tunneled_connection = Connection([b""])
        cases = (
            (Connection([b"CONNECT rejected.invalid:443 HTTP/1.1\r\nHost: rejected.invalid:443\r\n\r\n"]),
             HandshakeFailure(), "connect-admission", "ValueError", None),
            (Connection([connect]), HandshakeFailure(), "tls-handshake", "SSLError", None),
            (Connection([connect]), TunnelingTls(tunneled_connection), "tunneled-get", "EOFError",
             tunneled_connection),
        )
        for connection, tls, stage, exception_type, tunneled in cases:
            with self.subTest(stage=stage):
                diagnostics = []
                serve_connection(connection, tls, {"assets": []}, {}, b"{}",
                                 diagnostics.append)
                self.assertEqual([{
                    "request": "closed-or-rejected", "stage": stage,
                    "exceptionType": exception_type,
                }], diagnostics)
                if stage == "connect-admission":
                    self.assertIn(b"403 Forbidden", connection.sent)
                if tunneled is not None:
                    self.assertEqual(1, tunneled.closed)
                self.assertNotIn("private fixture detail", json.dumps(diagnostics))

    def test_java17_connect_host_without_port_is_admitted_only_for_exact_authority(self):
        class Connection:
            def __init__(self, data):
                self.data = bytearray(data)
                self.sent = bytearray()

            def recv(self, length):
                if not self.data:
                    return b""
                value = bytes(self.data[:length])
                del self.data[:length]
                return value

            def sendall(self, value):
                self.sent.extend(value)

            def close(self):
                pass

        class Tls:
            def wrap_socket(self, request, server_side):
                return Connection(b"")

        for authority, host, accepted in (
            ("github.com:443", "github.com", True),
            ("github.com:443", "github.com:443", True),
            ("github.com:444", "github.com", False),
            ("evil.invalid:443", "github.com", False),
            ("github.com:443", "evil.invalid", False),
        ):
            with self.subTest(authority=authority, host=host):
                connection = Connection((f"CONNECT {authority} HTTP/1.1\r\n"
                                         f"Host: {host}\r\n\r\n").encode())
                diagnostics = []
                serve_connection(connection, Tls(), {"assets": []}, {}, b"{}", diagnostics.append)
                if accepted:
                    self.assertIn(b"200 Connection Established", connection.sent)
                    self.assertEqual("tunneled-get", diagnostics[0]["stage"])
                else:
                    self.assertIn(b"403 Forbidden", connection.sent)
                    self.assertEqual("connect-admission", diagnostics[0]["stage"])

    def test_probe_event_requires_exact_manifest_get_and_is_immutable(self):
        probe_id = "34c822fc-3b71-4c34-b765-02f3e6db745b"
        manifest_body = b'{"schemaVersion":1,"assets":[]}'
        manifest_hash = hashlib.sha256(manifest_body).hexdigest()
        certificate_hash = "c" * 64
        connect = b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"

        class Connection:
            def __init__(self, data):
                self.data = data
                self.position = 0
                self.sent = bytearray()

            def recv(self, length):
                value = self.data[self.position:self.position + length]
                self.position += len(value)
                return value

            def sendall(self, value):
                self.sent.extend(value)

            def close(self):
                pass

        class Tls:
            def __init__(self, inner):
                self.inner = inner

            def wrap_socket(self, request, server_side):
                return self.inner

        def request(path=MANIFEST_PATH, probe=probe_id):
            return (f"GET {path} HTTP/1.1\r\nHost: github.com\r\n"
                    f"X-VPN-Control-Probe-Id: {probe}\r\n\r\n").encode()

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def exchange(path=MANIFEST_PATH, probe=probe_id):
                inner = Connection(request(path, probe))
                diagnostics = []
                serve_connection(Connection(connect), Tls(inner), {"assets": []}, {},
                                 manifest_body, diagnostics.append,
                                 probe_events_directory=directory,
                                 certificate_sha256=certificate_hash,
                                 server_instance_id="a6285846-10e4-45c5-9cf7-b138a5beb222")
                return inner, diagnostics

            inner, diagnostics = exchange()
            self.assertEqual([], diagnostics)
            self.assertIn(manifest_body, inner.sent)
            event_path = directory / "probe-events" / (probe_id + ".json")
            event = json.loads(event_path.read_text())
            self.assertEqual({"schemaVersion": 1, "correlationId": probe_id,
                              "serverInstanceId": "a6285846-10e4-45c5-9cf7-b138a5beb222",
                              "connectAccepted": True, "tlsSucceeded": True,
                              "exactManifestGet": True, "manifestSha256": manifest_hash,
                              "peerCertificateSha256": certificate_hash,
                              "servedBytes": len(manifest_body)}, event)
            if os.name == "posix":
                self.assertEqual(0o700, event_path.parent.stat().st_mode & 0o777)
                self.assertEqual(0o600, event_path.stat().st_mode & 0o777)
            original = event_path.read_bytes()
            _, diagnostics = exchange()
            self.assertEqual("ValueError", diagnostics[0]["exceptionType"])
            self.assertEqual(original, event_path.read_bytes())
            for path, probe in (("/wrong", "ac628584-610e-45c5-9cf7-b138a5beb222"),
                                (MANIFEST_PATH, "NOT-CANONICAL"),
                                (MANIFEST_PATH, "ac628584-610e-45c5-9cf7-b138a5beb222\r\n"
                                 "X-VPN-Control-Probe-Id: ac628584-610e-45c5-9cf7-b138a5beb222")):
                with self.subTest(path=path, probe=probe):
                    _, diagnostics = exchange(path, probe)
                    self.assertEqual("ValueError", diagnostics[0]["exceptionType"])
            self.assertEqual([probe_id + ".claim", probe_id + ".json"],
                             sorted(path.name for path in event_path.parent.iterdir()))

    def test_probe_event_is_absent_when_tls_handshake_fails(self):
        class Connection:
            def __init__(self, data):
                self.data = bytearray(data)
                self.sent = bytearray()

            def recv(self, length):
                value = bytes(self.data[:length])
                del self.data[:length]
                return value

            def sendall(self, value):
                self.sent.extend(value)

        class FailedTls:
            def wrap_socket(self, request, server_side):
                raise ssl.SSLError("private handshake detail")

        connect = Connection(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
        with tempfile.TemporaryDirectory() as temporary:
            diagnostics = []
            serve_connection(connect, FailedTls(), {"assets": []}, {}, b"{}",
                             diagnostics.append, probe_events_directory=Path(temporary),
                             certificate_sha256="c" * 64)
            self.assertEqual("tls-handshake", diagnostics[0]["stage"])
            self.assertFalse((Path(temporary) / "probe-events").exists())
            self.assertNotIn("private handshake detail", json.dumps(diagnostics))

    def test_probe_certificate_digest_uses_first_der_leaf_not_pem_chain(self):
        leaf, issuer = b"leaf certificate DER", b"issuer certificate DER"
        def pem(value):
            return ("-----BEGIN CERTIFICATE-----\n" +
                    base64.b64encode(value).decode("ascii") +
                    "\n-----END CERTIFICATE-----\n")
        with tempfile.TemporaryDirectory() as temporary:
            certificate = Path(temporary) / "chain.pem"
            certificate.write_text(pem(leaf) + pem(issuer))
            self.assertEqual(hashlib.sha256(leaf).hexdigest(),
                             prepare_desktop_update_fixture.probe_certificate_sha256(certificate))



class ArchFixturePlanTest(unittest.TestCase):
    def test_explicit_arch_plan_omits_deb_rpm_while_default_retains_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = DesktopUpdateFixtureTest()
            repository, runtime = helper.source(root)
            default = prepare(repository, root / "default", "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            arch = prepare(repository, root / "arch", "2.1.2", "2.1.3", runtime, "linux", "x86_64", "arch")
            default_tasks = default["stages"][0]["command"]
            arch_tasks = arch["stages"][0]["command"]
            self.assertIn(":desktopApp:packageDeb", default_tasks, "former plan reaches unsupported Arch DEB task")
            self.assertIn(":desktopApp:packageRpm", default_tasks)
            self.assertNotIn(":desktopApp:packageDeb", arch_tasks)
            self.assertNotIn(":desktopApp:packageRpm", arch_tasks)
            self.assertEqual("arch", arch["packageFamily"])
            self.assertEqual("default", default["packageFamily"])


class ArchFixtureEmissionTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "physical arch bundle modes require POSIX")
    def test_arch_family_emits_only_arch_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            helper = DesktopUpdateFixtureTest()
            root=Path(temporary); repository, runtime=helper.source(root)
            output=root/"fixture"; prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64", "arch")
            calls, runner=helper.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
                    patch("prepare_desktop_update_fixture.require_linux_build_tools"), \
                    patch("prepare_desktop_update_fixture.require_jdk17") as jdk_check:
                receipt=native_build(output, True, runner)
            jdk_check.assert_called_once_with()
            self.assertTrue(all(":desktopApp:packageDeb" not in c[0] and ":desktopApp:packageRpm" not in c[0] for c in calls))
            self.assertEqual({"arch-bundle"}, {a["packageType"] for a in receipt["manifest"]["assets"]})


class FixtureArchiveExtractionTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "readonly archive permissions require POSIX")
    def test_delayed_extraction_handles_real_readonly_directory(self):
        from fixture_environment import extract_readonly_archive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source=root/"source"; source.mkdir(); (source/"child").write_text("ok")
            (source/"child").chmod(0o400)
            source.chmod(0o500)
            archive=root/"fixture.tar.gz"; subprocess.run(["tar", "-C", str(root), "-czf", str(archive), "source"], check=True)
            output=root/"out"; extract_readonly_archive(archive, output)
            self.assertEqual("ok", (output/"source/child").read_text())
            self.assertEqual(0o500, (output/"source").stat().st_mode & 0o777)
            self.assertEqual(0o400, (output/"source/child").stat().st_mode & 0o777)


class FixtureEntrypointStagingTest(unittest.TestCase):
    def test_incomplete_stage_reports_the_observed_missing_fixture_environment_module(self):
        """CP105 copied only the command and could not reach fixture readiness."""
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "stage"
            stage.mkdir()
            shutil.copy2(Path(prepare_desktop_update_fixture.__file__),
                         stage / "prepare_desktop_update_fixture.py")
            with self.assertRaisesRegex(ValueError, r"ModuleNotFoundError.*fixture_environment"):
                validate_staged_fixture_entrypoint(stage)

    def test_staging_copies_all_runtime_modules_and_imports_the_actual_entrypoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "stage"
            source = Path(prepare_desktop_update_fixture.__file__).parent
            self.assertEqual(FIXTURE_ENTRYPOINT_MODULES, fixture_entrypoint_modules(source))
            receipt = stage_fixture_entrypoint(source, stage)
            self.assertEqual(list(FIXTURE_ENTRYPOINT_MODULES), receipt["modules"])
            self.assertEqual(set(FIXTURE_ENTRYPOINT_MODULES), {path.name for path in stage.iterdir()})
            # A second check exercises the staged command from another temporary
            # working directory, with no source checkout available on PYTHONPATH.
            validate_staged_fixture_entrypoint(stage)

    def test_undeclared_direct_local_import_is_rejected_before_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            original = Path(prepare_desktop_update_fixture.__file__).parent
            for name in FIXTURE_ENTRYPOINT_MODULES:
                shutil.copy2(original / name, source / name)
            (source / "new_local_dependency.py").write_text("", encoding="utf-8")
            entrypoint = source / FIXTURE_ENTRYPOINT_MODULES[0]
            entrypoint.write_text(entrypoint.read_text(encoding="utf-8") + "\nimport new_local_dependency\n",
                                  encoding="utf-8")
            stage = Path(temporary) / "stage"
            with self.assertRaisesRegex(ValueError, r"undeclared local imports: new_local_dependency"):
                stage_fixture_entrypoint(source, stage)
            self.assertFalse(stage.exists(), "stale inventory must fail before creating a staging directory")


if __name__ == "__main__":
    unittest.main()

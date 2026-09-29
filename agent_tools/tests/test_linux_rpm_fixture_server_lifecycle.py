"""No-replay and bounded guest-entry tests for the Fedora fixture endpoint."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from agent_tools import linux_rpm_fixture_server_lifecycle as route
from agent_tools import linux_rpm_fixture_server_guest as guest


CORRELATION = "12345678-1234-1234-1234-123456789abc"
SOURCE = "a" * 40


def request():
    return {"sourceSha": SOURCE, "scenarioId": "linux-rpm-public-install-recovery",
            "host": "fedora2328", "environment": "fedora2328", "bundleHash": "b" * 64,
            "artifactIds": {"bundleManifest": "sha256-" + "b" * 64,
                            "scenarioInput": "sha256-" + "c" * 64,
                            "sourceFixture": "sha256-" + "d" * 64,
                            "targetPackage": "sha256-" + "e" * 64},
            "credentialHandle": "rpm-auth-" + "f" * 32,
            "correlationId": CORRELATION}


class LinuxRpmFixtureServerLifecycleTest(unittest.TestCase):
    def test_request_accepts_only_full_fixed_fedora_public_intent(self):
        parsed, intent = route._request(request())
        self.assertEqual(SOURCE, parsed["sourceSha"])
        self.assertEqual(CORRELATION, intent.correlation_id)
        for changed in ({**request(), "host": "archlinux"},
                        {**request(), "environment": "other"},
                        {**request(), "arbitraryCommand": "true"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                route._request(changed)

    def test_server_admission_requires_public_authorization_before_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parsed, intent = route._request(request())
            with mock.patch.object(route.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=SOURCE + "\n")), \
                 mock.patch.object(route.rpm, "admission", side_effect=ValueError("authorization absent")) as gate:
                with self.assertRaisesRegex(ValueError, "authorization absent"):
                    route._admit(root, parsed, intent)
            gate.assert_called_once_with(root, intent)
            self.assertFalse((root / route._STATE).exists())

    def test_ready_for_public_requires_same_intent_and_live_server_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, intent = route._request(request())
            record = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                      "sourceFingerprint": "f" * 64,
                      "publicIntentSha256": hashlib.sha256(route._canonical(intent.public_mapping())).hexdigest(),
                      "authorizationHandleSha256": hashlib.sha256(intent.credential_handle.encode()).hexdigest()}
            route._save_journal(root, record)
            ready = {"state": "ready", "correlationId": CORRELATION,
                     "sourceSha": SOURCE, "publicIntentSha256": record["publicIntentSha256"]}
            with mock.patch.object(route.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=SOURCE + "\n")), \
                 mock.patch.object(route, "status", return_value=ready):
                self.assertTrue(route.ready_for_public(root, intent, "f" * 64))
                self.assertFalse(route.ready_for_public(root, intent, "e" * 64))
                changed = request()
                changed["credentialHandle"] = "rpm-auth-" + "a" * 32
                _, other = route._request(changed)
                self.assertFalse(route.ready_for_public(root, other, "f" * 64))

    def test_start_journals_before_guest_effect_and_never_replays_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                      "publicIntentSha256": "1" * 64}
            captured = {"public": public, "remoteRoot": "/private/fedora",
                        "config": object()}
            def payload(_root, _captured, path):
                path.write_bytes(b"fixed payload")
                return {"agent_tools/linux_rpm_fixture_server_guest.py":
                        {"size": 13, "sha256": hashlib.sha256(b"fixed payload").hexdigest()},
                        "agent_tools/linux_rpm_fixture_server.py":
                        {"size": 13, "sha256": "3" * 64}}
            def interrupted(_captured, _program, _args, _payload):
                journal = route._journal(root, CORRELATION)
                self.assertEqual(public.items() <= journal.items(), True)
                self.assertEqual(hashlib.sha256(b"fixed payload").hexdigest(), journal["payloadSha256"])
                return None
            with mock.patch.object(route, "_admit", return_value=captured), \
                    mock.patch.object(route, "_payload", side_effect=payload), \
                    mock.patch.object(route, "_remote", side_effect=interrupted) as remote:
                first = route.start(root, request())
                self.assertEqual("unknown", first["state"])
                self.assertFalse(first["replayAllowed"])
                with self.assertRaisesRegex(ValueError, "already has an intent"):
                    route.start(root, request())
                self.assertEqual(1, remote.call_count)

    def test_status_does_not_promote_unbound_or_dead_guest_server(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                      "publicIntentSha256": "1" * 64, "serverGuestSha256": "2" * 64,
                      "serverGuardSha256": "3" * 64}
            route._save_journal(root, record)
            config = mock.Mock(hosts={"fedora2328": mock.Mock(user="vpnfixture",
                fixture_transfer_root=Path("/private/fedora"))})
            with mock.patch.object(route.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(route, "_remote", return_value={"state": "ready",
                        "correlationId": CORRELATION, "sourceSha": "f" * 40,
                        "publicIntentSha256": "1" * 64}):
                self.assertEqual("unknown", route.status(root, {"correlationId": CORRELATION})["state"])
            with mock.patch.object(route.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(route, "_remote", return_value=None):
                self.assertEqual("unknown", route.collect(root, {"correlationId": CORRELATION})["state"])

    def test_embedded_guest_transport_programs_compile(self):
        compile(route._SUBMIT, "<rpm-fixture-server-submit>", "exec")
        compile(route._STATUS, "<rpm-fixture-server-status>", "exec")
        compile(Path(guest.__file__).read_text(), "<rpm-fixture-server-guest>", "exec")

    def test_staged_fixture_server_resolves_sibling_import_in_isolated_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "scripts"
            stage.mkdir()
            source = Path(__file__).resolve().parents[2] / "scripts"
            for name in ("prepare_desktop_update_fixture.py", "fixture_environment.py",
                         "macos_packaging_jdk_preflight.py"):
                candidate = source / name
                if candidate.exists():
                    shutil.copyfile(candidate, stage / name)
            script = stage / "prepare_desktop_update_fixture.py"
            old = subprocess.run(["python3", "-I", "-B", str(script), "--help"],
                                 capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, old.returncode)
            self.assertIn("fixture_environment", old.stderr)
            fixed = subprocess.run(guest._isolated_script_argv(script, "--help"),
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(0, fixed.returncode, fixed.stderr[-300:])

    def test_guest_executes_only_host_bound_guard_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            path = stage / "linux-rpm-fixture-server.py"
            original = b"def admit_endpoint(*_): return {'safe': True}\n"
            path.write_bytes(original)
            path.chmod(0o600)
            expected = hashlib.sha256(original).hexdigest()
            self.assertTrue(guest._verified_guard(stage, expected)["admit_endpoint"]()["safe"])
            path.write_bytes(b"def admit_endpoint(*_): return {'safe': False}\n")
            with self.assertRaisesRegex(ValueError, "guard changed"):
                guest._verified_guard(stage, expected)

    @unittest.skipUnless(shutil.which("openssl") and shutil.which("java"),
                         "requires local OpenSSL and Java source-file mode")
    def test_jdk17_passwordless_trust_store_contains_one_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert = root / "fixture.pem"
            key = root / "fixture.key"
            trust = root / "fixture.p12"
            generated = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=github.com",
                "-addext", "subjectAltName=DNS:github.com"], capture_output=True, timeout=30)
            self.assertEqual(0, generated.returncode)
            source = root / "MakeTrust.java"
            source.write_text(guest._MAKE_TRUST_JAVA)
            result = subprocess.run(["java", str(source), str(cert), str(trust)],
                                    capture_output=True, timeout=60)
            self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace")[-300:])
            self.assertGreater(trust.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()

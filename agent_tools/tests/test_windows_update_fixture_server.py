"""Causal fail-closed tests for CP117 HTTPS fixture server admission."""
from __future__ import annotations

import ast
import base64
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
import fcntl
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_tools import windows_update_fixture_server as server
_scripts = str(Path(__file__).resolve().parents[2] / "scripts")
sys.path.insert(0, _scripts)
try:
    from scripts import prepare_desktop_update_fixture as fixture
finally:
    sys.path.remove(_scripts)


LEASE = "11111111-1111-4111-8111-111111111111"
STAGE = "22222222-2222-4222-8222-222222222222"
SERVER = "33333333-3333-4333-8333-333333333333"
PROBE = "44444444-4444-4444-8444-444444444444"
INSTANCE = "55555555-5555-4555-8555-555555555555"
SOURCE = "a" * 40
SHA = "b" * 64
PAIR = {"sourceFingerprint": "c" * 64, "targetVersion": "2.2.0",
        "targetMsiSha256": "d" * 64, "targetMsiSize": 1234}
REQUEST = {"host": "archlinux", "leaseId": LEASE, "stageCorrelationId": STAGE,
           "serverCorrelationId": SERVER, "sourceSha": SOURCE,
           "fixtureReceiptArtifactId": "sha256-" + SHA,
           "baseMsiArtifactId": "sha256-" + "e" * 64,
           "targetMsiArtifactId": "sha256-" + PAIR["targetMsiSha256"]}
GUEST = ("/fixed/cp117.qga", 713, 1241, "S-1-5-21-1-2-3-1000")
MANIFEST = {"schemaVersion": 1, "buildNumber": 20400, "assets": [{"platform": "windows", "architecture": "x86_64",
            "fileName": "vpn-control-2.2.0.msi", "displayVersion": "2.2.0",
            "sha256": PAIR["targetMsiSha256"], "sizeBytes": PAIR["targetMsiSize"],
            "url": "https://private.invalid/target.msi"}]}
DESCRIPTOR = {"pythonExeSha256": "1" * 64, "launchCommandSha256": "2" * 64,
              "peerCertificateSha256": "3" * 64, "privateKeySha256": "4" * 64,
              "trustStoreSha256": "5" * 64, "certificateSha256": "6" * 64,
              "provisionId": "66666666-6666-4666-8666-666666666666"}


def evidence():
    body = json.dumps(MANIFEST, separators=(",", ":")).encode()
    ready = {"port": 49731, "serverInstanceId": INSTANCE, "serverPid": 811,
             "serverProcessStartIdentity": "windows:12457890",
             "sourceFingerprint": PAIR["sourceFingerprint"],
             "fixtureReceiptSha256": SHA, "manifestSha256": hashlib.sha256(body).hexdigest(),
             "peerCertificateSha256": DESCRIPTOR["peerCertificateSha256"],
             "manifest": copy.deepcopy(MANIFEST)}
    observed = {"qgaSocketPath": GUEST[0], "qemuPid": GUEST[1], "qemuStartTicks": GUEST[2],
                "serverPid": ready["serverPid"],
                "serverProcessStartIdentity": ready["serverProcessStartIdentity"],
                "serverInstanceId": INSTANCE, "originalSid": GUEST[3], "sessionId": 1,
                "limited": True, "listenerAddress": "127.0.0.1", "listenerPort": ready["port"],
                "listenerPid": ready["serverPid"], "taskState": "Running",
                "pythonExeSha256": DESCRIPTOR["pythonExeSha256"],
                "launchCommandSha256": DESCRIPTOR["launchCommandSha256"],
                "certificateSha256": DESCRIPTOR["certificateSha256"],
                "privateKeySha256": DESCRIPTOR["privateKeySha256"],
                "trustStoreSha256": DESCRIPTOR["trustStoreSha256"],
                "credentialProvisionId": DESCRIPTOR["provisionId"]}
    return ready, observed, len(body)


class FixtureServerAdmissionTest(unittest.TestCase):
    def test_start_requires_exact_request_without_private_urls_or_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extra in ({"certificatePath": "C:\\secret.pem"}, {"manifestUrl": "https://private.invalid"}):
                with self.assertRaises(server.WindowsUpdateFixtureServerError):
                    server.start(tmp, {**REQUEST, **extra})

    def test_missing_private_certificate_key_trust_blocks_before_remote_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(server, "_python_inventory", return_value={"path": "fixed", "sha256": "1" * 64,
                                                               "version": "3.13.15"}), \
                 patch.object(server, "_private_tls_descriptor", side_effect=server.WindowsUpdateFixtureServerError(
                    "FIXTURE_SERVER_CREDENTIAL_DESCRIPTOR_UNAVAILABLE")), \
                 patch.object(server, "_admit_campaign", return_value=(PAIR, GUEST)) as admission:
                with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "CREDENTIAL_DESCRIPTOR_UNAVAILABLE"):
                    server.start(tmp, REQUEST)
                admission.assert_not_called()

    def test_python_preflight_requires_unique_signed_fixed_interpreter(self):
        candidate = {"path": r"C:\Users\vpncp117\AppData\Local\Programs\Python\Python313\python.exe",
                     "sha256": "7" * 64, "version": "3.13.15",
                     "signer": "CN=Python Software Foundation"}
        descriptor = (object(), object(), ("windows-cp117", *GUEST))
        def response(candidates):
            return json.dumps({"state": "observed", "inventory":
                               {"version": 1, "candidates": candidates}}).encode()
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server, "_admit_campaign"), \
             patch.object(server.base, "_descriptor", return_value=descriptor), \
             patch.object(server.base, "_remote", return_value=response([candidate])) as remote:
            result = server.python_preflight(tmp, REQUEST)
            self.assertEqual(result["pythonExeSha256"], "7" * 64)
            self.assertFalse(result["serverReady"])
            self.assertNotIn(candidate["path"], json.dumps(result))
            for changed in ([candidate, candidate],
                            [],
                            [{**candidate, "path": r"C:\Temp\python.exe"}],
                            [{**candidate, "signer": "CN=Unknown"}],
                            [{**candidate, "sha256": "0" * 63}]):
                with self.subTest(changed=changed):
                    remote.return_value = response(changed)
                    with self.assertRaises(server.WindowsUpdateFixtureServerError):
                        server.python_preflight(tmp, REQUEST)
            remote.return_value = json.dumps({"state": "observed", "inventory": None}).encode()
            with self.assertRaises(server.WindowsUpdateFixtureServerError):
                server.python_preflight(tmp, REQUEST)

    def test_existing_intent_is_unknown_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / server._GROUP / (SERVER + ".json")
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"request": REQUEST, "state": "submitted"}))
            os.chmod(path, 0o600)
            with patch.object(server, "_admit_campaign") as admission:
                result = server.start(tmp, REQUEST)
            self.assertEqual(result, {"state": "unknown", "serverCorrelationId": SERVER,
                                      "cleanupRequired": True, "replayAllowed": False})
            admission.assert_not_called()
            self.assertEqual(server.status(tmp, {"serverCorrelationId": SERVER})["cleanupRequired"], True)

    def test_new_campaign_rejects_unknown_history_but_keeps_remote_closed_history(self):
        old = {**REQUEST, "leaseId": STAGE, "serverCorrelationId": PROBE,
               "stageCorrelationId": SERVER}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / server._GROUP
            directory.mkdir(parents=True, mode=0o700)
            path = directory / (PROBE + ".json")
            path.write_text(json.dumps({"schemaVersion": 1, "request": old}))
            os.chmod(path, 0o600)
            record = {"request": REQUEST}
            with patch.object(server.base, "_descriptor", return_value=(object(), object(), None)), \
                 patch.object(server.base, "_campaign_remote", return_value=lambda *_: None), \
                 patch.object(server.lease, "_locked", side_effect=lambda _root: (Path(tmp), os.open(Path(tmp), os.O_RDONLY))), \
                 patch.object(server.lease, "_closed", return_value={"state": "closed"}), \
                 patch.object(server.lease, "_remote_confirm", return_value=False) as confirm:
                with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "history"):
                    server._reserve(root, record)
                self.assertFalse((directory / (SERVER + ".json")).exists())
                confirm.return_value = True
                server._reserve(root, record)
                self.assertIsNotNone(server._read_intent(root, SERVER))
                self.assertEqual(confirm.call_args.args[1], "status")
            self.assertIn("closed.json", server._REMOTE_START)
            self.assertIn("binding.json", server._REMOTE_START)

    def test_remote_journals_stay_private_with_permissive_umask(self):
        namespace = {"json": json, "os": os, "stat": stat}
        exec(compile(ast.parse(server._PRIVATE_REMOTE_JSON), "private-remote-json", "exec"), namespace)
        writer = namespace["save_private_json"]
        with tempfile.TemporaryDirectory() as tmp:
            old = os.umask(0o022)
            try:
                unsafe = Path(tmp) / "old-open-x.json"
                with unsafe.open("x", encoding="utf-8") as stream:
                    json.dump({"pid": 1}, stream)
                self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o644)
                for name in ("start-binding", "start-dispatch", "cleanup-binding", "cleanup-dispatch"):
                    path = Path(tmp) / (name + ".json")
                    writer(str(path), {"pid": 1})
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    with self.assertRaises(FileExistsError):
                        writer(str(path), {"pid": 2})
            finally:
                os.umask(old)
        self.assertEqual(server._REMOTE_START.count("save_private_json(os.path.join("), 3)
        self.assertEqual(server._REMOTE_CLEANUP.count("save_private_json(os.path.join("), 3)
        self.assertNotIn("'x',encoding", server._REMOTE_START + server._REMOTE_CLEANUP)

    def test_lost_server_role_claim_keeps_durable_intent_without_guest_submission(self):
        credential_root = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                           + STAGE)
        descriptor = {**DESCRIPTOR, "paths": {"directory": credential_root,
            "certificate": credential_root + r"\server-cert.pem",
            "privateKey": credential_root + r"\server-key.pem",
            "trustStore": credential_root + r"\fixture-trust.p12"}}
        python = {"path": r"C:\Users\vpncp117\AppData\Local\Programs\Python\Python313\python.exe",
                  "sha256": "1" * 64, "version": "3.13.15"}
        host = type("Host", (), {"fixture_transfer_root": Path("/fixture")})()
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server, "_python_inventory", return_value=python), \
             patch.object(server, "_private_tls_descriptor", return_value=descriptor), \
             patch.object(server, "_admit_campaign", return_value=(PAIR, GUEST)), \
             patch.object(server.stage, "status", return_value={"fileHashes":
                          {"server/prepare_desktop_update_fixture.py": "8" * 64}}), \
             patch.object(server.base, "_descriptor", return_value=(object(), host,
                          ("windows-cp117", *GUEST))), \
             patch.object(server.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(server.lease, "claim_role", return_value={"state": "unknown"}) as claim, \
             patch.object(server.base, "_remote") as guest_submit:
            result = server.start(tmp, REQUEST)
            self.assertEqual(result["state"], "unknown")
            self.assertTrue(result["cleanupRequired"])
            self.assertFalse(result["replayAllowed"])
            self.assertIsNotNone(server._read_intent(Path(tmp), SERVER))
            claim.assert_called_once()
            guest_submit.assert_not_called()
            self.assertEqual(server.start(tmp, REQUEST)["state"], "unknown")
            claim.assert_called_once()
            guest_submit.assert_not_called()

    def test_static_files_cannot_claim_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = server.collect(tmp, {"serverCorrelationId": SERVER})
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["cleanupRequired"])
            with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "LIVE_FIXTURE_RECEIPT_UNAVAILABLE"):
                server.verified_live_receipt(tmp, LEASE)

    def test_status_finishes_start_role_only_after_fresh_live_receipt(self):
        live = {"serverInstanceId": INSTANCE, "serverPid": 811,
                "serverProcessStartIdentity": "windows:12457890",
                "manifestSha256": "a" * 64, "peerCertificateSha256": "b" * 64,
                "targetMsiSha256": PAIR["targetMsiSha256"]}
        live["liveReceiptSha256"] = hashlib.sha256(json.dumps(
            live, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        current = {"state": "role-active", "role": "server-start", "server": "starting"}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server, "_read_intent", return_value={"request": REQUEST}), \
             patch.object(server, "_live_from_intent", return_value=(live, current, object(), object())), \
             patch.object(server.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(server.lease, "finish_role", return_value={"state": "unknown"}) as finish:
            (Path(tmp) / server._GROUP).mkdir(parents=True)
            unknown = server.status(tmp, {"serverCorrelationId": SERVER})
            self.assertEqual(unknown["state"], "unknown")
            self.assertTrue(unknown["cleanupRequired"])
            self.assertEqual(finish.call_args.args[1:6],
                             (LEASE, "server-start", SERVER, live["liveReceiptSha256"], "succeeded"))
            finish.return_value = {"state": "active"}
            observed = server.status(tmp, {"serverCorrelationId": SERVER})
            self.assertEqual(observed["state"], "live")
            self.assertEqual(observed["liveReceiptSha256"], live["liveReceiptSha256"])

    def test_internal_live_join_discovers_one_private_intent_without_caller_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / server._GROUP
            directory.mkdir(parents=True, mode=0o700)
            path = directory / (SERVER + ".json")
            path.write_text(json.dumps({"request": REQUEST}))
            os.chmod(path, 0o600)
            receipt = {"leaseId": LEASE, "serverReady": True, "liveReceiptSha256": "a" * 64}
            with patch.object(server, "_live_from_intent", return_value=(
                       receipt, {"server": "live"}, None, None)) as live:
                self.assertEqual(server.verified_live_receipt(tmp, LEASE), receipt)
                live.assert_called_once()
                with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "UNAVAILABLE"):
                    server.verified_live_receipt(tmp, STAGE)
            (directory / (PROBE + ".json")).write_text("{}")
            with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "UNAVAILABLE"):
                server.verified_live_receipt(tmp, LEASE)

    def test_campaign_join_rejects_another_source_or_guest_generation(self):
        identity = {"host": "archlinux", "environment": "windows-cp117", "leaseId": LEASE,
                    "operator": "windows-base", "sourceSha": SOURCE,
                    "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                    "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                    "targetMsiArtifactId": REQUEST["targetMsiArtifactId"],
                    "socketPath": GUEST[0], "qemuPid": GUEST[1], "startTicks": GUEST[2]}
        stage_result = {"state": "staged-not-server-ready", "sourceSha": SOURCE,
                        "targetMsiSha256": PAIR["targetMsiSha256"]}
        with tempfile.TemporaryDirectory() as tmp:
            with (patch.object(server.public, "_admit_pair", return_value=PAIR),
                  patch.object(server.base, "_descriptor", return_value=(None, None, ("windows-cp117", *GUEST))),
                  patch.object(server.stage, "status", return_value=stage_result),
                  patch.object(server.lease, "inspect", return_value={"state": "active", "server": "stopped", "role": None}),
                  patch.object(server.lease, "_active", return_value={"identity": identity}) as active):
                pair, guest = server._admit_campaign(Path(tmp), REQUEST)
                self.assertEqual((pair, guest), (PAIR, GUEST))
                for changed in ({**identity, "sourceSha": "0" * 40},
                                {**identity, "startTicks": GUEST[2] + 1}):
                    active.return_value = {"identity": changed}
                    with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "identity changed"):
                        server._admit_campaign(Path(tmp), REQUEST)

    def test_python_preflight_does_not_finish_an_active_stage_role(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server.public, "_admit_pair", return_value=PAIR), \
             patch.object(server.base, "_descriptor", return_value=(None, None, ("windows-cp117", *GUEST))), \
             patch.object(server.lease, "inspect", return_value={"state": "role-active", "server": "stopped", "role": "stage"}), \
             patch.object(server.stage, "status") as stage_status:
            with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "not ready"):
                server._admit_campaign(Path(tmp), REQUEST)
            stage_status.assert_not_called()

    def test_fresh_live_ready_requires_exact_process_and_artifact_generation(self):
        ready, observed, _ = evidence()
        live = server._validate_live_ready(ready, observed, request=REQUEST, pair=PAIR,
                                           manifest=MANIFEST, descriptor=DESCRIPTOR, guest=GUEST)
        self.assertEqual(live["state"], "live")
        self.assertTrue(live["cleanupRequired"])
        self.assertNotIn("url", json.dumps(live).lower())
        receipt = server._live_receipt(REQUEST, PAIR, ready, observed, MANIFEST,
                                       DESCRIPTOR, GUEST)
        self.assertEqual({key: receipt[key] for key in ("leaseId", "sourceSha",
                         "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId",
                         "socketPath", "qemuPid", "startTicks", "serverReady")},
                         {"leaseId": LEASE, "sourceSha": SOURCE,
                          "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                          "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                          "targetMsiArtifactId": REQUEST["targetMsiArtifactId"],
                          "socketPath": GUEST[0], "qemuPid": GUEST[1], "startTicks": GUEST[2],
                          "serverReady": True})
        self.assertEqual(len(receipt["liveReceiptSha256"]), 64)
        self.assertNotIn("private.invalid", json.dumps(receipt))
        cases = [
            ("stale instance", "ready", "serverInstanceId", SERVER),
            ("changed source", "ready", "sourceFingerprint", "0" * 64),
            ("forged receipt", "ready", "fixtureReceiptSha256", "0" * 64),
            ("forged manifest", "ready", "manifestSha256", "0" * 64),
            ("forged certificate", "ready", "peerCertificateSha256", "0" * 64),
            ("changed asset", "ready_manifest", "sha256", "0" * 64),
            ("stale qemu", "observed", "qemuStartTicks", 1242),
            ("stale process", "observed", "serverProcessStartIdentity", "windows:999"),
            ("wrong listener", "observed", "listenerPid", 812),
            ("wrong sid", "observed", "originalSid", "S-1-5-18"),
            ("wrong session", "observed", "sessionId", 0),
            ("wrong trust", "observed", "trustStoreSha256", "0" * 64),
        ]
        for label, where, key, value in cases:
            with self.subTest(label=label):
                r, o = copy.deepcopy(ready), copy.deepcopy(observed)
                if where == "ready": r[key] = value
                elif where == "ready_manifest": r["manifest"]["assets"][0][key] = value
                else: o[key] = value
                with self.assertRaises(server.WindowsUpdateFixtureServerError):
                    server._validate_live_ready(r, o, request=REQUEST, pair=PAIR,
                                                manifest=MANIFEST, descriptor=DESCRIPTOR, guest=GUEST)

    def test_probe_event_must_match_public_response_and_live_instance(self):
        ready, observed, body_size = evidence()
        live = server._validate_live_ready(ready, observed, request=REQUEST, pair=PAIR,
                                           manifest=MANIFEST, descriptor=DESCRIPTOR, guest=GUEST)
        event = {"schemaVersion": 1, "correlationId": PROBE, "serverInstanceId": INSTANCE,
                 "connectAccepted": True, "tlsSucceeded": True, "exactManifestGet": True,
                 "manifestSha256": live["manifestSha256"],
                 "peerCertificateSha256": live["peerCertificateSha256"], "servedBytes": body_size}
        probe = {"correlationId": PROBE, "manifestSha256": live["manifestSha256"],
                 "peerCertificateSha256": live["peerCertificateSha256"],
                 "manifestBuildNumber": live["manifestBuildNumber"],
                 "availableVersion": "2.2.0", "assetSha256": live["targetMsiSha256"],
                 "assetSizeBytes": live["targetMsiSize"]}
        self.assertEqual(server._validate_probe_event(event, probe, live,
                         probe_correlation_id=PROBE, manifest_bytes=body_size)["state"], "correlated")
        for key, value in (("serverInstanceId", SERVER), ("correlationId", STAGE),
                           ("peerCertificateSha256", "0" * 64), ("servedBytes", body_size - 1)):
            with self.subTest(key=key):
                changed = {**event, key: value}
                with self.assertRaises(server.WindowsUpdateFixtureServerError):
                    server._validate_probe_event(changed, probe, live,
                                                 probe_correlation_id=PROBE, manifest_bytes=body_size)
        with self.assertRaises(server.WindowsUpdateFixtureServerError):
            server._validate_probe_event(event, {**probe, "assetSha256": "0" * 64}, live,
                                         probe_correlation_id=PROBE, manifest_bytes=body_size)
        with self.assertRaises(server.WindowsUpdateFixtureServerError):
            server._validate_probe_event(event, {**probe, "availableVersion": "2.3.0"}, live,
                                         probe_correlation_id=PROBE, manifest_bytes=body_size)

    def test_qga_live_observer_binds_private_ready_to_current_generation(self):
        ready, observed, _ = evidence()
        stage_root = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-" + STAGE)
        credentials = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                       + STAGE)
        descriptor = {**DESCRIPTOR, "paths": {
            "directory": credentials,
            "certificate": credentials + r"\server-cert.pem",
            "privateKey": credentials + r"\server-key.pem",
            "trustStore": credentials + r"\fixture-trust.p12"}}
        python = {"path": r"C:\Users\vpncp117\AppData\Local\Programs\Python\Python313\python.exe",
                  "sha256": DESCRIPTOR["pythonExeSha256"], "version": "3.13.15"}
        args = server._launch_arguments(REQUEST, descriptor)
        self.assertFalse(credentials.startswith(stage_root + r"\server-state"))
        observed["launchCommandSha256"] = hashlib.sha256(args.encode()).hexdigest()
        native = {"state": "observed", "result": {"schemaVersion": 1,
                   "ready": ready, "observed": observed}}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server.base, "_descriptor", return_value=(None, None, ("windows-cp117", *GUEST))), \
             patch.object(server.base, "_remote", return_value=json.dumps(native).encode()) as remote, \
             patch.object(server, "_fixture_manifest", return_value=MANIFEST):
            receipt = server._observe_live(Path(tmp), REQUEST, PAIR, descriptor, python, GUEST, args)
            self.assertTrue(receipt["serverReady"])
            self.assertNotIn("private.invalid", json.dumps(receipt))
            self.assertNotIn(descriptor["paths"]["privateKey"], json.dumps(receipt))
            remote.return_value = json.dumps({"state": "observed", "result":
                {"schemaVersion": 1, "ready": ready,
                 "observed": {**observed, "listenerPid": observed["listenerPid"] + 1}}}).encode()
            with self.assertRaises(server.WindowsUpdateFixtureServerError):
                server._observe_live(Path(tmp), REQUEST, PAIR, descriptor, python, GUEST, args)
            remote.return_value = json.dumps(native).encode()
            with patch.object(server.base, "_descriptor", return_value=(None, None,
                             ("windows-cp117", GUEST[0], GUEST[1], GUEST[2] + 1, GUEST[3]))):
                with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "generation changed"):
                    server._observe_live(Path(tmp), REQUEST, PAIR, descriptor, python, GUEST, args)

    def test_exact_source_serve_rejects_credential_child_inside_server_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ("mcp-update-fixture-" + STAGE)
            content = root / "content"
            state = root / "server-state"
            content.mkdir(parents=True)
            state.mkdir()
            (state / "credentials").mkdir()
            with patch.object(fixture.platform, "system", return_value="Windows"), \
                 patch.object(fixture, "require_fixture_certificate_current"), \
                 patch.object(fixture, "require_windows_private_acl", return_value=GUEST[3]):
                with self.assertRaisesRegex(ValueError, "state root is not fresh"):
                    fixture.serve(content, Path(tmp) / "cert.pem", Path(tmp) / "key.pem",
                                  state / "ready.json", True)

    def test_stop_claim_is_one_shot_and_does_not_dispatch_after_unknown_claim(self):
        cleanup = {"leaseId": LEASE, "serverCorrelationId": SERVER,
                   "cleanupCorrelationId": PROBE}
        server_intent = {"request": REQUEST, "environment": "windows-cp117",
                         "socketPath": GUEST[0], "qemuPid": GUEST[1],
                         "startTicks": GUEST[2], "originalSid": GUEST[3]}
        live = {"serverCorrelationId": SERVER, "serverPid": 811,
                "serverProcessStartIdentity": "windows:12457890", "serverPort": 49731}
        target = type("Host", (), {"fixture_transfer_root": Path("/fixture")})()
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server, "_read_intent", return_value=server_intent), \
             patch.object(server, "verified_live_receipt", return_value=live), \
             patch.object(server.base, "_descriptor", return_value=(object(), target,
                          ("windows-cp117", *GUEST))), \
             patch.object(server, "_cleanup_script", return_value="Write-Output safe"), \
             patch.object(server, "_private_tls_descriptor", return_value=DESCRIPTOR), \
             patch.object(server, "_cleanup_verify_script", return_value="Write-Output safe"), \
             patch.object(server.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(server.lease, "claim_role", return_value={"state": "unknown"}) as claim, \
             patch.object(server.base, "_remote") as guest_action:
            first = server.stop_start(tmp, cleanup)
            self.assertEqual(first["state"], "unknown")
            self.assertTrue(first["cleanupRequired"])
            self.assertFalse(first["replayAllowed"])
            self.assertIsNotNone(server._read_cleanup_intent(Path(tmp), PROBE))
            self.assertEqual(server.stop_start(tmp, cleanup)["state"], "unknown")
            claim.assert_called_once()
            guest_action.assert_not_called()

    def test_dead_after_ready_stops_from_durable_exact_live_generation(self):
        cleanup = {"leaseId": LEASE, "serverCorrelationId": SERVER,
                   "cleanupCorrelationId": PROBE}
        ready, observed, _ = evidence()
        live = server._live_receipt(REQUEST, PAIR, ready, observed, MANIFEST, DESCRIPTOR, GUEST)
        server_intent = {"request": REQUEST, "environment": "windows-cp117",
                         "socketPath": GUEST[0], "qemuPid": GUEST[1],
                         "startTicks": GUEST[2], "originalSid": GUEST[3]}
        target = type("Host", (), {"fixture_transfer_root": Path("/fixture")})()
        identity = {"leaseId": LEASE}
        current = {"identity": identity, "state": "active", "role": None,
                   "server": "live", "credentials": "ready"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / server._GROUP).mkdir(parents=True, mode=0o700)
            server._save_live_snapshot(root, SERVER, live)
            with patch.object(server, "_read_intent", return_value=server_intent), \
                 patch.object(server, "verified_live_receipt", side_effect=server.WindowsUpdateFixtureServerError(
                     "Live process exited")), \
                 patch.object(server.base, "_descriptor", return_value=(object(), target,
                              ("windows-cp117", *GUEST))), \
                 patch.object(server.public, "_admit_pair", return_value=PAIR), \
                 patch.object(server.base, "_campaign_identity", return_value=identity), \
                 patch.object(server.lease, "_active", return_value=current), \
                 patch.object(server.lease, "_remote_confirm", return_value=True), \
                 patch.object(server.base, "_campaign_remote", return_value=lambda *_: None), \
                 patch.object(server, "_cleanup_script", return_value="Write-Output safe"), \
                 patch.object(server, "_private_tls_descriptor", return_value=DESCRIPTOR), \
                 patch.object(server, "_cleanup_verify_script", return_value="Write-Output safe"), \
                 patch.object(server.lease, "claim_role", return_value={"state": "unknown"}) as claim, \
                 patch.object(server.base, "_remote") as guest_action:
                outcome = server.stop_start(root, cleanup)
                self.assertEqual(outcome["state"], "unknown")
                intent = server._read_cleanup_intent(root, PROBE)
                self.assertEqual(intent["serverPid"], live["serverPid"])
                self.assertEqual(intent["serverPort"], live["serverPort"])
                claim.assert_called_once()
                guest_action.assert_not_called()
                with self.assertRaises(server.WindowsUpdateFixtureServerError):
                    server._save_live_snapshot(root, SERVER, {**live, "serverPid": 812})
                with patch.object(server.base, "_descriptor", return_value=(object(), target,
                                 ("windows-cp117", GUEST[0], GUEST[1], GUEST[2] + 1, GUEST[3]))):
                    with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "generation changed"):
                        server._verified_stopped_live_snapshot(root, REQUEST)

    def test_abort_without_prior_dispatch_is_explicitly_unknown_before_qga_action(self):
        source = server._REMOTE_CLEANUP
        body = source[source.index("root,env,lease_id,role,role_corr,server_corr,"):]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job = root / "windows-cp117" / "windows-update-fixture-server" / SERVER
            job.mkdir(parents=True, mode=0o700)
            for private in (root, job.parent.parent, job.parent, job):
                os.chmod(private, 0o700)
            binding = {"leaseId": LEASE, "serverCorrelationId": SERVER,
                       "socketPath": GUEST[0], "qemuPid": GUEST[1], "startTicks": GUEST[2],
                       "sourceSha": SOURCE, "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                       "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                       "targetMsiArtifactId": REQUEST["targetMsiArtifactId"],
                       "dispatchProtocol": 2, "commandSha256": "c" * 64}
            path = job / "binding.json"
            path.write_text(json.dumps(binding))
            os.chmod(path, 0o600)
            script = b"safe"
            verify = b"read-only"
            encoded = base64.b64encode(script).decode()
            verify_encoded = base64.b64encode(verify).decode()
            arguments = [str(root), "windows-cp117", LEASE, "server-start", SERVER,
                         SERVER, PROBE, GUEST[0], str(GUEST[1]), str(GUEST[2]), SOURCE,
                         REQUEST["fixtureReceiptArtifactId"], REQUEST["baseMsiArtifactId"],
                         REQUEST["targetMsiArtifactId"], GUEST[3], encoded,
                         hashlib.sha256(script).hexdigest(), verify_encoded,
                         hashlib.sha256(verify).hexdigest()]
            calls = []
            namespace = {"os": os, "stat": stat, "json": json, "hashlib": hashlib,
                         "base64": base64, "fcntl": fcntl, "uuid": uuid,
                         "sys": type("Argv", (), {"argv": ["remote", *arguments]})(),
                         "live": lambda *_: True, "require_campaign_role": lambda *_: None,
                         "call": lambda *args: calls.append(args),
                         "save_private_json": lambda *_: self.fail("No cleanup journal before dispatch proof")}
            output = io.StringIO()
            with redirect_stdout(output):
                exec(compile(body, "remote-cleanup-body", "exec"), namespace)
            self.assertEqual(json.loads(output.getvalue())["state"], "unknown")
            self.assertEqual(calls, [])
            self.assertFalse((job / ("cleanup-" + PROBE)).exists())
            lock_path = job / ".dispatch.lock"
            lock_path.write_bytes(b"")
            os.chmod(lock_path, 0o600)
            marker_path = job / "guest-dispatch-intent.json"
            marker_path.write_text(json.dumps({"commandSha256": binding["commandSha256"]}))
            os.chmod(marker_path, 0o600)
            output = io.StringIO()
            with redirect_stdout(output):
                exec(compile(body, "remote-cleanup-body", "exec"), namespace)
            self.assertEqual(json.loads(output.getvalue())["state"], "unknown")
            self.assertEqual(calls, [])
            self.assertFalse((job / ("cleanup-" + PROBE)).exists())
            marker_path.unlink()
            namespace["save_private_json"] = None
            exec(compile(ast.parse(server._PRIVATE_REMOTE_JSON), "private-remote-json", "exec"), namespace)
            def read_only_call(_socket, operation, payload):
                calls.append((operation, payload))
                if operation == "guest-exec":
                    return {"pid": 456}
                return {"exited": True, "exitcode": 0, "out-truncated": False,
                        "err-truncated": False, "out-data": base64.b64encode(json.dumps(
                            {"taskAbsent": True, "matchingProcessAbsent": True,
                             "listenerAbsent": True}).encode()).decode()}
            namespace["call"] = read_only_call
            namespace["decode"] = lambda raw: raw.decode()
            output = io.StringIO()
            with redirect_stdout(output):
                exec(compile(body, "remote-cleanup-body", "exec"), namespace)
            self.assertEqual(json.loads(output.getvalue())["state"], "submitted")
            self.assertEqual(calls[0][0], "guest-exec")
            self.assertEqual(calls[0][1]["arg"][-1], verify_encoded)
            cleanup = job / ("cleanup-" + PROBE)
            self.assertFalse((cleanup / "dispatch.json").exists())
            self.assertEqual(stat.S_IMODE((cleanup / "terminal.json").stat().st_mode), 0o600)
            status_source = server._REMOTE_CLEANUP_STATUS
            status_body = status_source[status_source.index("root,env,lease_id,role,role_corr,server_corr,"):]
            status_arguments = [str(root), "windows-cp117", LEASE, "server-start", SERVER,
                                SERVER, PROBE, GUEST[0], str(GUEST[1]), str(GUEST[2]), SOURCE,
                                REQUEST["fixtureReceiptArtifactId"], REQUEST["baseMsiArtifactId"],
                                REQUEST["targetMsiArtifactId"], verify_encoded,
                                hashlib.sha256(script).hexdigest(), hashlib.sha256(verify).hexdigest()]
            namespace["sys"] = type("Argv", (), {"argv": ["remote", *status_arguments]})()
            output = io.StringIO()
            with redirect_stdout(output):
                exec(compile(status_body, "remote-cleanup-status-body", "exec"), namespace)
            status = json.loads(output.getvalue())
            self.assertEqual(status["state"], "observed")
            self.assertEqual(status["terminal"]["serverPid"], 0)
            self.assertTrue(status["fresh"]["taskAbsent"])

    def test_abort_requires_exact_active_server_start_before_cleanup_intent(self):
        cleanup = {"leaseId": LEASE, "serverCorrelationId": SERVER,
                   "cleanupCorrelationId": PROBE}
        server_intent = {"request": REQUEST, "environment": "windows-cp117",
                         "socketPath": GUEST[0], "qemuPid": GUEST[1],
                         "startTicks": GUEST[2], "originalSid": GUEST[3]}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server, "_read_intent", return_value=server_intent), \
             patch.object(server.base, "_descriptor", return_value=(object(),
                          type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                          ("windows-cp117", *GUEST))), \
             patch.object(server.lease, "_active", return_value={"state": "active"}), \
             patch.object(server, "_reserve_cleanup") as reserve:
            with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "cannot be aborted"):
                server.abort_start(tmp, cleanup)
            reserve.assert_not_called()

    def test_cleanup_status_requires_terminal_and_fresh_absence_before_lease_finish(self):
        cleanup = {"leaseId": LEASE, "serverCorrelationId": SERVER,
                   "cleanupCorrelationId": PROBE}
        intent = {"mode": "stop", "request": cleanup, "serverRequest": REQUEST,
                  "environment": "windows-cp117", "socketPath": GUEST[0],
                  "qemuPid": GUEST[1], "startTicks": GUEST[2], "originalSid": GUEST[3],
                  "serverPid": 811, "serverProcessStartIdentity": "windows:12457890",
                  "serverPort": 49731, "commandSha256": "8" * 64,
                  "verifyCommandSha256": "9" * 64}
        server_intent = {"request": REQUEST, "credentialProvisionId": DESCRIPTOR["provisionId"],
                         **{key: DESCRIPTOR[key] for key in ("peerCertificateSha256",
                             "certificateSha256", "privateKeySha256", "trustStoreSha256")}}
        identity = {"leaseId": LEASE}
        current = {"state": "role-active", "role": "server-stop", "correlationId": PROBE,
                   "server": "stopping", "credentials": "ready", "identity": identity}
        absence = {"taskAbsent": True, "matchingProcessAbsent": True, "listenerAbsent": True}
        terminal = {**absence, "originalSid": GUEST[3], "sessionId": 1,
                    "serverPid": 811, "serverProcessStartIdentity": "windows:12457890",
                    "serverPort": 49731}
        native = {"state": "observed", "cleanupCorrelationId": PROBE,
                  "terminal": terminal, "fresh": {**absence, "matchingProcessAbsent": False}}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server, "_read_cleanup_intent", return_value=intent), \
             patch.object(server, "_read_intent", return_value=server_intent), \
             patch.object(server.base, "_descriptor", return_value=(object(),
                          type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                          ("windows-cp117", *GUEST))), \
             patch.object(server.base, "_campaign_identity", return_value=identity), \
             patch.object(server.lease, "_active", return_value=current), \
             patch.object(server.lease, "_remote_confirm", return_value=True), \
             patch.object(server.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(server, "_private_tls_descriptor", return_value=DESCRIPTOR), \
             patch.object(server, "_cleanup_verify_script", return_value="safe"), \
             patch.object(server.base, "_remote", return_value=json.dumps(native).encode()) as remote, \
             patch.object(server.lease, "finish_role", return_value={"state": "active"}) as finish:
            (Path(tmp) / server._CLEANUP_GROUP).mkdir(parents=True)
            self.assertEqual(server.stop_status(tmp, {"cleanupCorrelationId": PROBE})["state"], "unknown")
            finish.assert_not_called()
            native["fresh"] = absence
            remote.return_value = json.dumps(native).encode()
            result = server.stop_status(tmp, {"cleanupCorrelationId": PROBE})
            finish.assert_called_once()
            self.assertEqual(result["state"], "stopped")
            self.assertEqual(len(result["cleanupReceiptSha256"]), 64)
            self.assertEqual(finish.call_args.args[2:6],
                             ("server-stop", PROBE, result["cleanupReceiptSha256"], "succeeded"))

    def test_abort_finishes_start_only_after_original_dispatch_and_fresh_absence(self):
        cleanup = {"leaseId": LEASE, "serverCorrelationId": SERVER,
                   "cleanupCorrelationId": PROBE}
        intent = {"mode": "abort", "request": cleanup, "serverRequest": REQUEST,
                  "environment": "windows-cp117", "socketPath": GUEST[0],
                  "qemuPid": GUEST[1], "startTicks": GUEST[2], "originalSid": GUEST[3],
                  "serverPid": 0, "serverProcessStartIdentity": "",
                  "serverPort": 0, "commandSha256": "8" * 64,
                  "verifyCommandSha256": "9" * 64}
        server_intent = {"request": REQUEST, "credentialProvisionId": DESCRIPTOR["provisionId"],
                         **{key: DESCRIPTOR[key] for key in ("peerCertificateSha256",
                             "certificateSha256", "privateKeySha256", "trustStoreSha256")}}
        identity = {"leaseId": LEASE}
        current = {"state": "role-active", "role": "server-start", "correlationId": SERVER,
                   "server": "starting", "credentials": "ready", "identity": identity}
        absence = {"taskAbsent": True, "matchingProcessAbsent": True, "listenerAbsent": True}
        native = {"state": "observed", "cleanupCorrelationId": PROBE,
                  "terminal": {**absence, "originalSid": GUEST[3], "sessionId": 1,
                               "serverPid": 0, "serverProcessStartIdentity": "", "serverPort": 0},
                  "fresh": absence}
        target = type("Host", (), {"fixture_transfer_root": Path("/fixture")})()
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server, "_read_cleanup_intent", return_value=intent), \
             patch.object(server, "_read_intent", return_value=server_intent), \
             patch.object(server.base, "_descriptor", return_value=(object(), target,
                          ("windows-cp117", *GUEST))), \
             patch.object(server.base, "_campaign_identity", return_value=identity), \
             patch.object(server.lease, "_active", return_value=current), \
             patch.object(server.lease, "_remote_confirm", return_value=True), \
             patch.object(server.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(server, "_private_tls_descriptor", return_value=DESCRIPTOR), \
             patch.object(server, "_cleanup_verify_script", return_value="safe"), \
             patch.object(server.base, "_remote", return_value=json.dumps(native).encode()), \
             patch.object(server.lease, "finish_role", return_value={"state": "active"}) as finish:
            (Path(tmp) / server._CLEANUP_GROUP).mkdir(parents=True)
            observed = server.abort_status(tmp, {"cleanupCorrelationId": PROBE})
            self.assertEqual(observed["state"], "stopped")
            self.assertEqual(finish.call_args.args[2:6],
                             ("server-start", SERVER, observed["cleanupReceiptSha256"], "failed-cleaned"))
            self.assertIn("prior_state=call(sock,'guest-exec-status'", server._REMOTE_CLEANUP)
            self.assertLess(server._REMOTE_CLEANUP.index("require_campaign_role"),
                            server._REMOTE_CLEANUP.index("child=call(sock,'guest-exec'"))


if __name__ == "__main__":
    unittest.main()

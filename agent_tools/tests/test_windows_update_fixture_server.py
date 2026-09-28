"""Causal fail-closed tests for CP117 HTTPS fixture server admission."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_update_fixture_server as server


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
              "trustStoreSha256": "5" * 64}


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
                "certificateSha256": DESCRIPTOR["peerCertificateSha256"],
                "privateKeySha256": DESCRIPTOR["privateKeySha256"],
                "trustStoreSha256": DESCRIPTOR["trustStoreSha256"]}
    return ready, observed, len(body)


class FixtureServerAdmissionTest(unittest.TestCase):
    def test_start_requires_exact_request_without_private_urls_or_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extra in ({"certificatePath": "C:\\secret.pem"}, {"manifestUrl": "https://private.invalid"}):
                with self.assertRaises(server.WindowsUpdateFixtureServerError):
                    server.start(tmp, {**REQUEST, **extra})

    def test_missing_private_certificate_key_trust_blocks_before_remote_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(server, "_admit_campaign", return_value=(PAIR, GUEST)) as admission:
                with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "CREDENTIAL_DESCRIPTOR_UNAVAILABLE"):
                    server.start(tmp, REQUEST)
                admission.assert_not_called()

    def test_existing_intent_is_unknown_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / server._GROUP / (SERVER + ".json")
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"request": REQUEST, "state": "submitted"}))
            os.chmod(path, 0o600)
            with patch.object(server, "_admit_campaign") as admission:
                result = server.start(tmp, REQUEST)
            self.assertEqual(result, {"state": "unknown", "serverCorrelationId": SERVER,
                                      "replayAllowed": False})
            admission.assert_not_called()
            self.assertEqual(server.status(tmp, {"serverCorrelationId": SERVER})["cleanupRequired"], True)

    def test_static_files_cannot_claim_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = server.collect(tmp, {"serverCorrelationId": SERVER})
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["cleanupRequired"])
            with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "LIVE_FIXTURE_RECEIPT_UNAVAILABLE"):
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

    def test_fresh_live_ready_requires_exact_process_and_artifact_generation(self):
        ready, observed, _ = evidence()
        live = server._validate_live_ready(ready, observed, request=REQUEST, pair=PAIR,
                                           manifest=MANIFEST, descriptor=DESCRIPTOR, guest=GUEST)
        self.assertEqual(live["state"], "live")
        self.assertTrue(live["cleanupRequired"])
        self.assertNotIn("url", json.dumps(live).lower())
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


if __name__ == "__main__":
    unittest.main()

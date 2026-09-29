"""Causal CP117 public HTTPS transport-probe admission tests."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from agent_tools import windows_fixture_network_probe as probe


LEASE = "11111111-1111-4111-8111-111111111111"
STAGE = "22222222-2222-4222-8222-222222222222"
SERVER = "33333333-3333-4333-8333-333333333333"
CORR = "44444444-4444-4444-8444-444444444444"
CONTROLLER = "55555555-5555-4555-8555-555555555555"
INSTANCE = "66666666-6666-4666-8666-666666666666"
REQUEST = {"host": "archlinux", "leaseId": LEASE, "stageCorrelationId": STAGE,
           "serverCorrelationId": SERVER, "probeCorrelationId": CORR,
           "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64,
           "controllerId": CONTROLLER, "ownerPid": 4321,
           "ownerStartedAtUtc": "2026-09-29T10:00:00Z"}
BINDING = {**{key: REQUEST[key] for key in REQUEST if key != "host"},
           "originalSid": "S-1-5-21-1-2-3-1000", "socketPath": "/fixed/cp117.sock",
           "qemuPid": 1000, "startTicks": 2000, "serverInstanceId": INSTANCE,
           "serverPort": 45231, "liveReceiptSha256": "e" * 64,
           "manifestSha256": "f" * 64, "manifestBuildNumber": 16800,
           "peerCertificateSha256": "0" * 64, "trustStoreSha256": "1" * 64,
           "credentialProvisionId": "77777777-7777-4777-8777-777777777777",
           "targetVersion": "2.2.0", "targetMsiSha256": "2" * 64,
           "targetMsiSize": 1234, "baseCliSha256": "3" * 64}
OBSERVED = {"originalSid": BINDING["originalSid"], "sessionId": 1, "limited": True,
            "ownerPid": REQUEST["ownerPid"], "ownerStartedAtUtc": REQUEST["ownerStartedAtUtc"],
            "controllerId": CONTROLLER, "cliSha256": BINDING["baseCliSha256"],
            "proxyHost": "127.0.0.1", "proxyPort": BINDING["serverPort"],
            "trustStoreSha256": BINDING["trustStoreSha256"],
            "taskState": "Ready", "taskExitCode": 0,
            "ownerJvmNetworkVerified": True, "ownerJvmPid": REQUEST["ownerPid"],
            "ownerJvmStartedAtUtc": REQUEST["ownerStartedAtUtc"],
            "ownerJvmProxyPort": BINDING["serverPort"],
            "ownerJvmTrustStoreSha256": BINDING["trustStoreSha256"]}
DATA = {"correlationId": CORR, "manifestSha256": BINDING["manifestSha256"],
        "peerCertificateSha256": BINDING["peerCertificateSha256"],
        "manifestBuildNumber": BINDING["manifestBuildNumber"],
        "availableVersion": BINDING["targetVersion"],
        "assetSha256": BINDING["targetMsiSha256"],
        "assetSizeBytes": BINDING["targetMsiSize"]}
PUBLIC = {"code": "OK", "final": True, "controllerId": CONTROLLER, "data": DATA}
EVENT = {"schemaVersion": 1, "correlationId": CORR, "serverInstanceId": INSTANCE,
         "connectAccepted": True, "tlsSucceeded": True, "exactManifestGet": True,
         "manifestSha256": BINDING["manifestSha256"],
         "peerCertificateSha256": BINDING["peerCertificateSha256"], "servedBytes": 156}


class NetworkProbeTest(unittest.TestCase):
    def test_exact_request_excludes_authored_network_proof_and_paths(self):
        self.assertEqual(probe._request(REQUEST), REQUEST)
        for changed in ({"ready": True}, {"trustStore": r"C:\Temp\bad.p12"},
                        {"ownerPid": True}, {"probeCorrelationId": SERVER},
                        {"controllerId": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}):
            with self.subTest(changed=changed), self.assertRaises(probe.WindowsFixtureNetworkProbeError):
                probe._request({**REQUEST, **changed})

    def test_public_response_without_private_server_event_fails_causally(self):
        # A client-only OK result cannot prove that this live server served it.
        with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError, "Private server event"):
            probe._validate_evidence(BINDING, OBSERVED, PUBLIC, {}, manifest_bytes=156)
        receipt = probe._validate_evidence(BINDING, OBSERVED, PUBLIC, EVENT, manifest_bytes=156)
        self.assertTrue(receipt["ownerTransportVerified"])
        self.assertEqual(receipt["probeCorrelationId"], CORR)
        self.assertTrue(receipt["ownerJvmNetworkVerified"])
        digest = receipt.pop("probeReceiptSha256")
        self.assertEqual(digest, hashlib.sha256(json.dumps(
            receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def test_foreign_owner_proxy_trust_or_stale_server_event_fail_closed(self):
        for field, value in (("ownerPid", 5000), ("controllerId", LEASE),
                             ("proxyPort", 1111), ("trustStoreSha256", "4" * 64),
                             ("taskState", "Running"), ("taskExitCode", 1),
                             ("ownerJvmNetworkVerified", False),
                             ("ownerJvmPid", 9999),
                             ("ownerJvmStartedAtUtc", "2026-09-29T11:00:00Z"),
                             ("ownerJvmProxyPort", 1111),
                             ("ownerJvmTrustStoreSha256", "8" * 64)):
            with self.subTest(field=field), self.assertRaises(probe.WindowsFixtureNetworkProbeError):
                probe._validate_evidence(BINDING, {**OBSERVED, field: value}, PUBLIC, EVENT,
                                         manifest_bytes=156)
        for field, value in (("correlationId", LEASE), ("serverInstanceId", LEASE),
                             ("manifestSha256", "a" * 64), ("servedBytes", 155)):
            with self.subTest(field=field), self.assertRaises(probe.WindowsFixtureNetworkProbeError):
                probe._validate_evidence(BINDING, OBSERVED, PUBLIC, {**EVENT, field: value},
                                         manifest_bytes=156)
        with self.assertRaises(probe.WindowsFixtureNetworkProbeError):
            probe._validate_evidence(BINDING, OBSERVED,
                                     {**PUBLIC, "data": {**DATA, "assetSha256": "9" * 64}},
                                     EVENT, manifest_bytes=156)

    def test_start_is_inert_until_original_owner_dispatch_exists(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(probe, "_current_binding", return_value=BINDING):
            with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError,
                                        "ORIGINAL_OWNER_PROBE_DISPATCH_UNAVAILABLE"):
                probe.start(tmp, REQUEST)
            self.assertEqual(probe.status(tmp, {"probeCorrelationId": CORR}),
                             {"state": "unknown", "probeCorrelationId": CORR,
                              "cleanupRequired": False, "replayAllowed": False,
                              "ownerTransportVerified": False})
            with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError,
                                        "OWNER_NETWORK_RECEIPT_UNAVAILABLE"):
                probe.verified_owner_network_receipt(tmp, LEASE)

    def test_fixed_original_owner_task_and_observer_are_bounded(self):
        trust = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                 + STAGE + r"\fixture-trust.p12")
        body = probe._task_script(REQUEST, BINDING, trust)
        bootstrap = probe._bootstrap_script(REQUEST, BINDING, trust)
        observer = probe._observation_script(REQUEST, BINDING)
        self.assertIn("updates transport-probe $corr", body)
        self.assertIn("$env:JAVA_TOOL_OPTIONS=", body)
        self.assertIn("GetOwnerSid", body)
        self.assertIn("-RunLevel Limited", bootstrap)
        self.assertIn("Start-ScheduledTask", bootstrap)
        self.assertIn("probe-events", observer)
        self.assertNotIn("updates install", body + bootstrap + observer)
        self.assertNotIn("Start-ScheduledTask", observer)
        with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError, "fixed credential path"):
            probe._task_script(REQUEST, BINDING, r"C:\Temp\untrusted.p12")
        for script in (bootstrap, observer):
            self.assertLess(len(__import__("base64").b64encode(script.encode("utf-16le"))), 30000)

    def test_qga_observer_accepts_only_exact_public_and_private_pair(self):
        response = {"state": "observed", "result": {"schemaVersion": 1, "correlationId": CORR,
                    "observed": OBSERVED, "publicResponse": PUBLIC, "event": EVENT}}
        guest = ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                 BINDING["startTicks"], BINDING["originalSid"])
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(probe.base, "_descriptor", return_value=(object(), object(), guest)), \
             patch.object(probe.base, "_remote", return_value=json.dumps(response).encode()) as remote, \
             patch.object(probe.server, "_fixture_manifest", return_value={"x": 1}):
            # Real manifest byte count is derived by the server fixture reader.
            wrong = probe._observe_native
            with self.assertRaises(probe.WindowsFixtureNetworkProbeError):
                wrong(Path(tmp), REQUEST, BINDING)
            self.assertTrue(remote.called)
            observed = dict(response)
            observed["result"] = dict(response["result"], event={**EVENT, "servedBytes": 7})
            remote.return_value = json.dumps(observed).encode()
            self.assertEqual(probe._observe_native(Path(tmp), REQUEST, BINDING)["probeCorrelationId"], CORR)
            remote.return_value = None
            with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError, "QGA observation is unknown"):
                probe._observe_native(Path(tmp), REQUEST, BINDING)

    def test_one_shot_intent_precedes_effect_and_replay_stays_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe._reserve(root, REQUEST, BINDING)
            self.assertEqual(probe._read_intent(root, CORR)["binding"], BINDING)
            with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError, "history"):
                probe._reserve(root, {**REQUEST, "probeCorrelationId":
                             "88888888-8888-4888-8888-888888888888"}, BINDING)
            with patch.object(probe, "_current_binding") as admission:
                self.assertEqual(probe.start(root, REQUEST)["replayAllowed"], False)
                admission.assert_not_called()
            self.assertEqual(probe.status(root, {"probeCorrelationId": CORR})["state"], "unknown")

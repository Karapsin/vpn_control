"""Causal CP117 public HTTPS transport-probe admission tests."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from agent_tools import windows_fixture_network_probe as probe
from agent_tools import windows_fixture_owner_network as owner_network


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
           "ownerNetworkCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
           "ownerLaunchReceiptSha256": "a" * 64,
           "targetVersion": "2.2.0", "targetMsiSha256": "2" * 64,
           "targetMsiSize": 1234, "baseCliSha256": "3" * 64}
OBSERVED = {"originalSid": BINDING["originalSid"], "sessionId": 1, "limited": True,
            "ownerPid": REQUEST["ownerPid"], "ownerStartedAtUtc": REQUEST["ownerStartedAtUtc"],
            "controllerId": CONTROLLER, "cliSha256": BINDING["baseCliSha256"],
            "proxyHost": "127.0.0.1", "proxyPort": BINDING["serverPort"],
            "trustStoreSha256": BINDING["trustStoreSha256"],
            "taskState": "Ready", "taskExitCode": 0, "cleanupProofSha256": None,
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
OWNER_RECEIPT = {
    "ownerJvmNetworkVerified": False, "ownerNetworkCorrelationId": BINDING["ownerNetworkCorrelationId"],
    "ownerLaunchReceiptSha256": BINDING["ownerLaunchReceiptSha256"],
    **{key: BINDING[key] for key in ("leaseId", "sourceSha", "fixtureReceiptArtifactId",
                                   "baseMsiArtifactId", "targetMsiArtifactId", "stageCorrelationId",
                                   "serverCorrelationId", "socketPath", "qemuPid", "startTicks",
                                   "originalSid", "ownerPid", "ownerStartedAtUtc", "controllerId",
                                   "liveReceiptSha256")},
    "ownerJvmPid": REQUEST["ownerPid"], "ownerJvmStartedAtUtc": REQUEST["ownerStartedAtUtc"],
    "ownerJvmProxyPort": BINDING["serverPort"],
    "ownerJvmTrustStoreSha256": BINDING["trustStoreSha256"]}


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
        cleaned = probe._validate_evidence(
            BINDING, {**OBSERVED, "taskState": "AbsentCleaned", "cleanupProofSha256": "9" * 64},
            PUBLIC, EVENT, manifest_bytes=156)
        self.assertEqual(cleaned["probeTaskCleanupSha256"], "9" * 64)
        digest = receipt.pop("probeReceiptSha256")
        self.assertEqual(digest, hashlib.sha256(json.dumps(
            receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def test_foreign_owner_proxy_trust_or_stale_server_event_fail_closed(self):
        for field, value in (("ownerPid", 5000), ("controllerId", LEASE),
                             ("proxyPort", 1111), ("trustStoreSha256", "4" * 64),
                             ("taskState", "Running"), ("taskExitCode", 1),
                             ("cleanupProofSha256", "8" * 64),
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

    def test_public_start_dispatches_exact_original_owner_probe(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(probe, "_current_binding", return_value=BINDING), \
             patch.object(probe.lease, "_locked", side_effect=lambda *_:
                          (Path(tmp), os.open(os.devnull, os.O_RDONLY))), \
             patch.object(probe.lease, "_active", return_value={
                 "identity": {"leaseId": LEASE}, "state": "active", "role": None}), \
             patch.object(probe, "_submit_candidate", return_value={
                 "state": "submitted", "probeCorrelationId": CORR,
                 "cleanupRequired": True, "replayAllowed": False,
                 "ownerTransportVerified": False}) as submit:
            self.assertEqual(probe.start(tmp, REQUEST)["state"], "submitted")
            submit.assert_called_once_with(Path(tmp).resolve(), REQUEST, BINDING,
                probe._ROOT + r"\mcp-update-credentials-" + STAGE + r"\fixture-trust.p12")
            self.assertEqual(probe.status(tmp, {"probeCorrelationId": CORR}),
                             {"state": "unknown", "probeCorrelationId": CORR,
                              "cleanupRequired": False, "replayAllowed": False,
                              "ownerTransportVerified": False})
            with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError,
                                        "OWNER_NETWORK_RECEIPT_UNAVAILABLE"):
                probe.verified_owner_network_receipt(tmp, LEASE)

    def test_claimed_probe_rechecks_owner_binding_before_guest_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(probe.base, "_descriptor", return_value=(object(), object(),
                          ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                           BINDING["startTicks"], BINDING["originalSid"]))), \
             patch.object(probe.base, "_campaign_remote", return_value=object()), \
             patch.object(probe, "_reserve"), \
             patch.object(probe.lease, "claim_role", return_value={"state": "role-active"}), \
             patch.object(probe, "_current_binding", return_value={**BINDING,
                          "ownerPid": REQUEST["ownerPid"] + 1}), \
             patch.object(probe.base, "_remote") as remote:
            with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError,
                                        "binding changed after claim"):
                probe._submit_candidate(Path(tmp), REQUEST, BINDING,
                    probe._ROOT + r"\mcp-update-credentials-" + STAGE + r"\fixture-trust.p12")
            remote.assert_not_called()

    def test_start_rejects_target_role_before_reserving_probe_intent(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(probe, "_current_binding", return_value=BINDING), \
             patch.object(probe.lease, "_locked", side_effect=lambda *_:
                          (Path(tmp), os.open(os.devnull, os.O_RDONLY))), \
             patch.object(probe.lease, "_active", return_value={
                 "identity": {"leaseId": LEASE}, "state": "role-active",
                 "role": "target", "correlationId": "88888888-8888-4888-8888-888888888888"}), \
             patch.object(probe, "_submit_candidate") as submit:
            with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError,
                                        "idle campaign"):
                probe.start(tmp, REQUEST)
            self.assertIsNone(probe._read_intent(Path(tmp), CORR))
            submit.assert_not_called()

    def test_fixed_original_owner_task_and_observer_are_bounded(self):
        trust = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                 + STAGE + r"\fixture-trust.p12")
        body = probe._task_script(REQUEST, BINDING, trust)
        bootstrap = probe._bootstrap_script(REQUEST, BINDING, trust)
        observer = probe._observation_script(REQUEST, BINDING)
        cleanup = probe._cleanup_script(REQUEST, BINDING)
        self.assertIn("updates transport-probe $corr", body)
        self.assertIn("$env:JAVA_TOOL_OPTIONS=", body)
        self.assertIn("GetOwnerSid", body)
        self.assertIn("-RunLevel Limited", bootstrap)
        self.assertIn("Start-ScheduledTask", bootstrap)
        self.assertIn("probe-events", observer)
        self.assertIn("Unregister-ScheduledTask", cleanup)
        self.assertIn("task-cleanup.json", cleanup)
        self.assertNotIn("updates install", body + bootstrap + observer + cleanup)
        self.assertNotIn("Start-ScheduledTask", observer)
        with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError, "fixed credential path"):
            probe._task_script(REQUEST, BINDING, r"C:\Temp\untrusted.p12")
        for script in (bootstrap, observer, cleanup):
            self.assertLess(len(__import__("base64").b64encode(script.encode("utf-16le"))), 30000)

    def test_qga_cleanup_requires_exact_absence_and_action_digest(self):
        trust = (probe._ROOT + r"\mcp-update-credentials-" + STAGE + r"\fixture-trust.p12")
        action = "-NoProfile -NonInteractive -EncodedCommand " + __import__("base64").b64encode(
            probe._task_script(REQUEST, BINDING, trust).encode("utf-16le")).decode()
        result = {"schemaVersion": 1, "correlationId": CORR,
                  "taskName": "VpnControlMcpNetworkProbe-" + CORR,
                  "actionSha256": hashlib.sha256(action.encode()).hexdigest(),
                  "taskAbsent": True, "cleanupProofSha256": "4" * 64}
        guest = ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                 BINDING["startTicks"], BINDING["originalSid"])
        class Host: fixture_transfer_root = Path("/fixed/cp117")
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(probe.base, "_descriptor", return_value=(object(), Host(), guest)), \
             patch.object(probe.base, "_remote", return_value=json.dumps(
                 {"state": "observed", "result": result}).encode()) as remote:
            self.assertEqual(probe._cleanup_native(Path(tmp), REQUEST, BINDING), "4" * 64)
            for change in ({"taskAbsent": False}, {"actionSha256": "9" * 64},
                           {"cleanupProofSha256": "short"}, {"correlationId": LEASE}):
                remote.return_value = json.dumps({"state": "observed", "result": {**result, **change}}).encode()
                with self.subTest(change=change), self.assertRaises(probe.WindowsFixtureNetworkProbeError):
                    probe._cleanup_native(Path(tmp), REQUEST, BINDING)

    def test_lease_role_finishes_only_after_cleanup_and_fresh_readback(self):
        before = probe._validate_evidence(BINDING, OBSERVED, PUBLIC, EVENT, manifest_bytes=156)
        after = probe._validate_evidence(BINDING, {**OBSERVED, "taskState": "AbsentCleaned",
                "cleanupProofSha256": "9" * 64}, PUBLIC, EVENT, manifest_bytes=156)
        intent = {"request": REQUEST, "binding": BINDING, "state": "reserved"}
        current = {"identity": {"leaseId": LEASE}, "server": "live", "credentials": "ready",
                   "state": "role-active", "role": "network-probe", "correlationId": CORR}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(probe, "_read_intent", return_value=intent), \
             patch.object(probe, "_current_binding", return_value=BINDING), \
             patch.object(probe, "_observe_native", side_effect=[before, after]) as observed, \
             patch.object(probe, "_cleanup_native", side_effect=probe.WindowsFixtureNetworkProbeError("unknown")) as cleanup, \
             patch.object(probe.base, "_descriptor", return_value=(object(), object(), object())), \
             patch.object(probe.base, "_campaign_remote", return_value=object()), \
             patch.object(probe.lease, "_locked", side_effect=lambda *_:
                          (Path(tmp), os.open(os.devnull, os.O_RDONLY))), \
             patch.object(probe.lease, "_active", return_value=current), \
             patch.object(probe.lease, "finish_role", return_value={"state": "active"}) as finish, \
             patch.object(probe, "_write_terminal_receipt"):
            self.assertEqual(probe.status(tmp, {"probeCorrelationId": CORR})["state"], "unknown")
            finish.assert_not_called()
            # A lost cleanup response can leave the task already absent. The
            # next readback reconciles its private proof without replaying it.
            observed.side_effect = [after, after]
            cleanup.side_effect = None
            cleanup.return_value = "9" * 64
            self.assertEqual(probe.status(tmp, {"probeCorrelationId": CORR})["state"], "correlated")
            finish.assert_called_once()

    def test_qga_observer_accepts_only_exact_public_and_private_pair(self):
        qga_observed = {**OBSERVED, "ownerJvmNetworkVerified": False,
                        "ownerJvmPid": None, "ownerJvmStartedAtUtc": None,
                        "ownerJvmProxyPort": None, "ownerJvmTrustStoreSha256": None}
        response = {"state": "observed", "result": {"schemaVersion": 1, "correlationId": CORR,
                    "observed": qga_observed, "publicResponse": PUBLIC, "event": EVENT}}
        guest = ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                 BINDING["startTicks"], BINDING["originalSid"])
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(probe.base, "_descriptor", return_value=(object(), object(), guest)), \
             patch.object(probe.base, "_remote", return_value=json.dumps(response).encode()) as remote, \
             patch.object(probe.server, "_fixture_manifest", return_value={"x": 1}), \
             patch.object(probe.owner_network, "verified_owner_jvm_receipt", return_value=OWNER_RECEIPT):
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

    def test_owner_jvm_receipt_is_independent_of_forwarding_cli(self):
        probe._require_owner_jvm_receipt(REQUEST, BINDING, OWNER_RECEIPT)
        for changed in ({"ownerJvmNetworkVerified": True}, {"ownerJvmPid": 99},
                        {"ownerJvmProxyPort": 1}, {"ownerJvmTrustStoreSha256": "0" * 64},
                        {"ownerLaunchReceiptSha256": "short"}, {"liveReceiptSha256": "0" * 64}):
            with self.subTest(changed=changed), self.assertRaises(probe.WindowsFixtureNetworkProbeError):
                probe._require_owner_jvm_receipt(REQUEST, BINDING, {**OWNER_RECEIPT, **changed})

    def test_real_owner_launch_schema_joins_probe_only_at_new_generation(self):
        # This is the actual owner adapter's terminal validator, not a second
        # hand-authored mirror of its returned receipt shape.
        from agent_tools.tests import test_windows_fixture_owner_network as owner_fixture
        old = owner_fixture.REQUEST
        launch_binding = owner_fixture.BINDING
        new_controller = "99999999-9999-4999-8999-999999999999"
        record = {"schemaVersion": 1, "correlationId": old["ownerNetworkCorrelationId"],
                  "oldOwnerPid": old["ownerPid"], "oldOwnerStartedAtUtc": old["ownerStartedAtUtc"],
                  "oldControllerId": old["controllerId"], "newOwnerPid": 5321,
                  "newOwnerStartedAtUtc": "2026-09-29T10:00:00Z", "newControllerId": new_controller,
                  "originalSid": owner_fixture.SID, "sessionId": 1, "limited": True,
                  "cliSha256": launch_binding["baseCliSha256"], "proxyHost": "127.0.0.1",
                  "proxyPort": launch_binding["serverPort"],
                  "trustStoreSha256": launch_binding["trustStoreSha256"],
                  "runtimeOff": True, "launchSource": "limited-task-process-environment"}
        observed = {"schemaVersion": 1, "correlationId": old["ownerNetworkCorrelationId"],
                    "record": record, "taskState": "AbsentCleaned", "taskExitCode": 0,
                    "cleanupProofSha256": "9" * 64,
                    "ownerPid": 5321, "ownerStartedAtUtc": record["newOwnerStartedAtUtc"],
                    "controllerId": new_controller, "originalSid": owner_fixture.SID,
                    "sessionId": 1, "activeProcessCount": 0}
        actual = owner_network._validate_terminal(old, launch_binding, observed,
                                                   owner_fixture.PROVENANCE)
        self.assertIs(actual["ownerJvmNetworkVerified"], False)
        self.assertEqual(actual["ownerTaskCleanupSha256"], "9" * 64)
        request = {**REQUEST, "probeCorrelationId": "88888888-8888-4888-8888-888888888888",
                   "ownerPid": actual["ownerPid"],
                   "ownerStartedAtUtc": actual["ownerStartedAtUtc"],
                   "controllerId": actual["controllerId"]}
        binding = {**BINDING, "originalSid": actual["originalSid"],
                   "socketPath": actual["socketPath"], "qemuPid": actual["qemuPid"],
                   "startTicks": actual["startTicks"],
                   "serverPort": actual["ownerJvmProxyPort"],
                   "trustStoreSha256": actual["ownerJvmTrustStoreSha256"],
                   "liveReceiptSha256": actual["liveReceiptSha256"],
                   "ownerNetworkCorrelationId": actual["ownerNetworkCorrelationId"],
                   "ownerLaunchReceiptSha256": actual["ownerLaunchReceiptSha256"]}
        probe._require_owner_jvm_receipt(request, binding, actual)
        with self.assertRaises(probe.WindowsFixtureNetworkProbeError):
            probe._require_owner_jvm_receipt({**request, "ownerPid": old["ownerPid"]}, binding, actual)
        with self.assertRaises(probe.WindowsFixtureNetworkProbeError):
            probe._require_owner_jvm_receipt(request, {**binding,
                "ownerLaunchReceiptSha256": "0" * 64}, actual)

    def test_one_shot_intent_precedes_effect_and_replay_stays_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe._reserve(root, REQUEST, BINDING)
            self.assertEqual(probe._read_intent(root, CORR)["binding"], BINDING)
            next_request = {**REQUEST, "leaseId": "99999999-9999-4999-8999-999999999999",
                            "probeCorrelationId": "88888888-8888-4888-8888-888888888888"}
            closed = {"identity": {"leaseId": LEASE, "sourceSha": REQUEST["sourceSha"],
                      "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                      "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                      "targetMsiArtifactId": REQUEST["targetMsiArtifactId"]}}
            with patch.object(probe.base, "_descriptor", return_value=(object(), object(), object())), \
                 patch.object(probe.base, "_campaign_remote", return_value=lambda *_: b"ok"), \
                 patch.object(probe.lease, "_locked", side_effect=lambda *_:
                              (root, os.open(os.devnull, os.O_RDONLY))), \
                 patch.object(probe.lease, "_closed", return_value=closed) as prior, \
                 patch.object(probe.lease, "_remote_confirm", return_value=False) as remote:
                with self.assertRaisesRegex(probe.WindowsFixtureNetworkProbeError, "active or unknown"):
                    probe._reserve(root, next_request, BINDING)
                self.assertTrue(prior.called)
                remote.return_value = True
                probe._reserve(root, next_request, BINDING)
                self.assertEqual(probe._read_intent(root, next_request["probeCorrelationId"])["request"], next_request)
            with patch.object(probe, "_current_binding") as admission:
                self.assertEqual(probe.start(root, REQUEST)["replayAllowed"], False)
                admission.assert_not_called()
            self.assertEqual(probe.status(root, {"probeCorrelationId": CORR})["state"], "unknown")

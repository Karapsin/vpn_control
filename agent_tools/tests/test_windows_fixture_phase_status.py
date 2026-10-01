"""Causal regressions for the read-only CP117 fixture phase projection."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_fixture_phase_status as phases


CORRELATION = "03de8469-bcb2-49e4-a710-a3c4d1db3f64"
LEASE = "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926"
REQUEST = {"host": "archlinux", "correlationId": CORRELATION, "sourceSha": "a" * 40,
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}
RECORD = {"request": REQUEST, "leaseId": LEASE, "bundlePath": "/private/bundle.zip",
          "bundleSha256": "e" * 64, "bundleSize": 7, "routeNonce": "x" * 32,
          "sourceFingerprint": "f" * 64}
INTENT = {"request": REQUEST, "leaseId": LEASE, "environment": "windows-cp117",
          "socketPath": "/qga", "pid": 99, "startTicks": 100, "expectedSid": "S-1-5-21-1",
          "bundleSha256": "e" * 64, "bundleSize": 7, "sourceFingerprint": "f" * 64,
          "fileHashes": {}}
DESCRIPTOR = ("windows-cp117", "/qga", 99, 100, "S-1-5-21-1")


class FixturePhaseStatusTest(unittest.TestCase):
    def _bound(self):
        return (mock.patch.object(phases.http_stage, "_read", return_value=RECORD),
                mock.patch.object(phases.http_stage, "_artifact"),
                mock.patch.object(phases.stage, "_read_intent", return_value=INTENT),
                mock.patch.object(phases.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)),
                mock.patch.object(phases.campaign, "inspect", return_value={"state": "role-active", "leaseId": LEASE,
                                                                               "sequence": 2, "role": "stage", "server": "stopped", "replayAllowed": False}))

    def test_missing_intent_is_a_finite_pre_effect_fact_without_observation(self):
        with mock.patch.object(phases.http_stage, "_read", return_value=None), \
             mock.patch.object(phases, "_observe") as observe:
            result = phases.status(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("intent-absent", result["phase"])
        self.assertEqual("prepare-not-accepted", result["nextFact"])
        observe.assert_not_called()
        self.assertFalse(result["replayAllowed"])

    def test_lost_transfer_response_uses_saved_receipt_and_never_reissues_stage(self):
        patches = self._bound()
        with patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(phases, "_observe", return_value={"listener": "absent", "guest": "absent", "collect": "absent"}), \
             mock.patch.object(phases.http_stage, "stage_start") as stage_start, \
             mock.patch.object(phases.http_stage, "guest_download") as download:
            result = phases.status(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("transfer-unobserved", result["phase"])
        self.assertEqual("observe-transfer-receipt", result["nextFact"])
        stage_start.assert_not_called(); download.assert_not_called()

    def test_e66_terminal_pre_effect_close_precedes_listener_and_guest_observation(self):
        corr = phases.http_stage._E66_CORRELATION
        request = {**REQUEST, "correlationId": corr}
        record = {**RECORD, "request": request}
        intent = {**INTENT, "request": request}
        core = {"binding": phases.http_stage._large_binding(record, DESCRIPTOR),
                "phase": "aborted", "dispatchFailure": phases.http_stage._E66_FAILURE,
                "preEffectClose": {"reason": "source-not-path", "remoteStage": "absent"}}
        with (mock.patch.object(phases.http_stage, "_read", return_value=record),
              mock.patch.object(phases.http_stage, "_artifact"),
              mock.patch.object(phases.stage, "_read_intent", return_value=intent),
              mock.patch.object(phases.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)),
              mock.patch.object(phases.campaign, "inspect", return_value={"state": "role-active"}),
              mock.patch.object(phases.large_transfer, "read", return_value=core),
              mock.patch.object(phases.http_stage, "_e66_transcript", return_value={"transcriptSha256": "a" * 64}),
              mock.patch.object(phases.http_stage, "_e66_imported", return_value=True),
              mock.patch.object(phases, "_observe") as observe):
            result = phases.status(Path.cwd(), {"correlationId": corr})
        self.assertEqual("pre-effect-aborted", result["phase"])
        self.assertEqual("retire-aborted-stage", result["nextFact"])
        self.assertNotIn("observation", result)
        observe.assert_not_called()

    def test_lost_guest_create_response_is_not_promoted_past_listener_receipt(self):
        patches = self._bound()
        with patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(phases, "_observe", return_value={"listener": "listening", "guest": "absent", "collect": "absent"}):
            result = phases.status(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("guest-create-or-download-unobserved", result["phase"])
        self.assertEqual("observe-guest-receipt", result["nextFact"])

    def test_lost_download_response_recovers_a_verified_guest_receipt_without_extract_replay(self):
        patches = self._bound()
        with patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(phases, "_observe", return_value={"listener": "served", "guest": "downloaded", "collect": "absent"}), \
             mock.patch.object(phases.http_stage, "stage_extract") as extract:
            result = phases.status(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("extract-unobserved", result["phase"])
        self.assertEqual("observe-extract-receipt", result["nextFact"])
        extract.assert_not_called()

    def test_terminal_collect_observer_requires_exact_receipt_and_committed_digest(self):
        """A lost collect response resolves from a real read-only receipt path."""
        descriptor = ("windows-cp117", "/qga", 99, 100, "S-1-5-21-1-2-3-4")
        sid = descriptor[4]
        def acl(path, rights):
            return {"stage": path, "protected": True, "acl": [
                {"sid": "S-1-5-18", "rights": rights[0], "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
                {"sid": "S-1-5-32-544", "rights": rights[1], "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
                {"sid": sid, "rights": rights[2], "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
            ]}
        root = phases.stage._GUEST + "\\mcp-update-fixture-" + CORRELATION
        receipt = {"version": 1, "correlationId": CORRELATION,
                   "code": "STAGED_NOT_SERVER_READY", "bundleSha256": RECORD["bundleSha256"],
                   "files": {}, "acl": acl(root + "\\content", (0x1F01FF, 0x1F01FF, 0x1200A9)),
                   "rootAcl": acl(root, (0x1F01FF, 0x1F01FF, 0x1200A9)),
                   "stateAcl": acl(root + "\\server-state", (0x1F01FF, 0x1F01FF, 0x1F01FF))}
        digest = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        core = {"binding": phases.http_stage._large_binding(RECORD, descriptor), "phase": "placed"}
        campaign_record = {"identity": {"lease": LEASE}, "state": "active", "role": None,
                           "lastOutcome": "succeeded", "lastEvidenceSha256": digest}
        target = mock.Mock(fixture_transfer_root=Path("/fixture"))
        with tempfile.TemporaryDirectory() as directory:
            lock = os.open(Path(directory) / "lock", os.O_RDWR | os.O_CREAT, 0o600)
            with (mock.patch.object(phases.large_transfer, "read", return_value=core),
                  mock.patch.object(phases.campaign, "_locked", return_value=(Path(directory), lock)),
                  mock.patch.object(phases.campaign, "_active", return_value=campaign_record),
                  mock.patch.object(phases.base, "_campaign_identity", return_value={"lease": LEASE}),
                  mock.patch.object(phases.campaign, "_remote_confirm", return_value=True),
                  mock.patch.object(phases.base, "_remote", return_value=json.dumps({"state": "observed", "correlationId": CORRELATION, "result": receipt}).encode()),
                  mock.patch.object(phases.http_stage, "stage_start") as stage_start,
                  mock.patch.object(phases.http_stage, "stage_extract") as extract,
                  mock.patch.object(phases.http_stage, "collect") as collect):
                result = phases._terminal_collect(Path(directory), CORRELATION, RECORD, INTENT,
                                                  object(), target, descriptor)
        self.assertEqual("collected", result)
        stage_start.assert_not_called(); extract.assert_not_called(); collect.assert_not_called()

    def test_terminal_collect_rejects_same_receipt_when_campaign_has_not_committed_it(self):
        """The placed pre-effect marker cannot impersonate a collection receipt."""
        receipt = {"version": 1, "correlationId": CORRELATION,
                   "code": "STAGED_NOT_SERVER_READY", "bundleSha256": RECORD["bundleSha256"],
                   "files": {}, "acl": {}, "rootAcl": {}, "stateAcl": {}}
        core = {"binding": phases.http_stage._large_binding(RECORD, DESCRIPTOR), "phase": "placed"}
        campaign_record = {"identity": {"lease": LEASE}, "state": "role-active", "role": "stage",
                           "lastOutcome": None, "lastEvidenceSha256": None}
        target = mock.Mock(fixture_transfer_root=Path("/fixture"))
        with tempfile.TemporaryDirectory() as directory:
            lock = os.open(Path(directory) / "lock", os.O_RDWR | os.O_CREAT, 0o600)
            with (mock.patch.object(phases.large_transfer, "read", return_value=core),
                  mock.patch.object(phases.campaign, "_locked", return_value=(Path(directory), lock)),
                  mock.patch.object(phases.campaign, "_active", return_value=campaign_record),
                  mock.patch.object(phases.base, "_campaign_identity", return_value={"lease": LEASE}),
                  mock.patch.object(phases.campaign, "_remote_confirm", return_value=True),
                  mock.patch.object(phases.base, "_remote", return_value=json.dumps({"state": "observed", "correlationId": CORRELATION, "result": receipt}).encode()),
                  mock.patch.object(phases.stage, "validate_stage_acl_receipt"),
                  mock.patch.object(phases.stage, "_validate_state_acl")):
                result = phases._terminal_collect(Path(directory), CORRELATION, RECORD, INTENT,
                                                  object(), target, DESCRIPTOR)
        self.assertEqual("absent", result)

    def test_descriptor_or_campaign_mismatch_stops_before_host_or_guest_observation(self):
        patches = self._bound()
        with patches[0], patches[1], patches[2], mock.patch.object(phases.base, "_descriptor", return_value=(object(), object(), ("windows-cp117", "/changed", 99, 100, "S-1-5-21-1"))), \
             mock.patch.object(phases, "_observe") as observe:
            result = phases.status(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("vm-binding-mismatch", result["phase"])
        observe.assert_not_called()

    def test_public_contract_has_only_finite_values_and_is_read_only(self):
        self.assertEqual(frozenset({"intent-absent", "source-receipt-mismatch", "vm-binding-mismatch", "campaign-unbound", "transfer-unobserved", "guest-create-or-download-unobserved", "extract-unobserved", "collected", "observation-unknown", "pre-effect-aborted"}), phases.PHASES)
        self.assertTrue(all(isinstance(item, str) for item in phases.NEXT_FACTS))

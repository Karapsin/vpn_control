"""Causal checks for the one retired guest-create campaign successor."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from agent_tools import windows_cp117_guest_abort_successor as successor


NEW = "b1387ac6-bd49-470b-9e8d-399a44760329"
ARTIFACTS = {"fixtureReceiptArtifactId": "sha256-" + "a" * 64,
             "baseMsiArtifactId": "sha256-" + "b" * 64,
             "targetMsiArtifactId": "sha256-" + "c" * 64}
REQUEST = {"host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": NEW,
           "sourceSha": successor._SOURCE, **ARTIFACTS}
DESC = ("windows-cp117", "/qga", 20241, 98231, "S-1-5-21-1-2-3-1002")


class GuestAbortSuccessorTest(unittest.TestCase):
    def _old_request(self):
        return {"correlationId": successor._CORRELATION, "sourceSha": successor._SOURCE, **ARTIFACTS}

    def _receipt(self):
        evidence, digest = successor.abort._receipt_value(
            {"request": ARTIFACTS, "sourceFingerprint": "d" * 64, "bundleSha256": "e" * 64}, DESC)
        return evidence, digest

    def _active(self, digest):
        return {"identity": successor.base._campaign_identity({**self._old_request(), "correlationId": successor._OLD}, DESC),
                "state": "active", "role": None, "correlationId": None, "server": "stopped",
                "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": digest}

    def _admission(self, temporary):
        receipt, digest = self._receipt()
        record = {"leaseId": successor._OLD, "request": self._old_request(),
                  "sourceFingerprint": "d" * 64, "bundleSha256": "e" * 64, "bundleSize": 42}
        target = SimpleNamespace(fixture_transfer_root="/transfer")
        authority = successor.http._authority_binding(record, DESC)
        return (patch.object(successor.abort, "_admission", return_value=("retired", (Path(temporary), record, object(), target, DESC, receipt, digest))),
                patch.object(successor.base, "_descriptor", return_value=(object(), target, DESC)),
                patch.object(successor.lease, "_locked", return_value=(Path(temporary), 0)),
                patch.object(successor.os, "close"),
                patch.object(successor.lease, "_active", return_value=self._active(digest)),
                patch.object(successor, "_idle", return_value=True),
                patch.object(successor.base, "_remote", return_value=b'{"state":"cleaned"}'),
                patch.object(successor.lease, "_remote_confirm", return_value=True), receipt, digest, authority)

    def test_exact_retired_abort_closes_then_reserves_distinct_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            patches = self._admission(temporary)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
                 patch.object(successor.lease, "close", return_value={"state": "closed"}) as close, \
                 patch.object(successor.lease, "begin", return_value={"state": "active"}) as begin:
                result = successor.start(temporary, REQUEST)
        self.assertEqual({"state": "active", "leaseId": NEW, "replayAllowed": False, "nativeActionAllowed": False}, result)
        self.assertEqual(successor._OLD, close.call_args.args[1])
        self.assertEqual(NEW, begin.call_args.args[1]["leaseId"])

    def test_causal_regression_changed_abort_proof_blocks_before_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            patches = self._admission(temporary)
            evidence, _ = self._receipt(); evidence["hostCleanup"] = "tampered"
            bad_record = {"leaseId": successor._OLD, "request": self._old_request(),
                          "sourceFingerprint": "d" * 64, "bundleSha256": "e" * 64, "bundleSize": 42}
            bad_details = (Path(temporary), bad_record, object(), SimpleNamespace(fixture_transfer_root="/transfer"), DESC, evidence, successor._digest(evidence))
            with patch.object(successor.abort, "_admission", return_value=("retired", bad_details)), \
                 patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
                 patch.object(successor.lease, "close") as close:
                result = successor.start(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        close.assert_not_called()

    def test_causal_regression_request_cannot_change_source_or_old_lease(self):
        changed = dict(REQUEST); changed["sourceSha"] = "f" * 40
        with self.assertRaises(successor.WindowsCp117GuestAbortSuccessorError): successor._request(changed)
        changed = dict(REQUEST); changed["oldLeaseId"] = "00000000-0000-4000-8000-000000000000"
        with self.assertRaises(successor.WindowsCp117GuestAbortSuccessorError): successor._request(changed)

    def test_reconcile_does_not_call_close_or_begin(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", side_effect=successor.WindowsCp117GuestAbortSuccessorError()), \
                 patch.object(successor.lease, "close") as close, patch.object(successor.lease, "begin") as begin:
                result = successor.reconcile(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        close.assert_not_called(); begin.assert_not_called()

    def test_resume_begin_requires_durable_intent_before_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", side_effect=successor.WindowsCp117GuestAbortSuccessorError()), \
                 patch.object(successor.lease, "begin") as begin:
                result = successor.resume_begin(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        begin.assert_not_called()

    def test_causal_regression_status_rejects_local_successor_without_remote_closed_proof(self):
        old_request = self._old_request()
        old_identity = successor.base._campaign_identity({**old_request, "correlationId": successor._OLD}, DESC)
        new_identity = successor.base._campaign_identity({**old_request, "correlationId": NEW}, DESC)
        old = {"identity": old_identity, "state": "closed", "role": None, "correlationId": None,
               "server": "stopped", "credentials": "absent", "lastOutcome": "failed-cleaned",
               "lastEvidenceSha256": successor._cleanup(DESC, "f" * 64)["cleanupReceiptSha256"]}
        new = {"identity": new_identity, "state": "active", "role": None, "correlationId": None,
               "server": "stopped", "credentials": "absent", "sequence": 0,
               "lastEvidenceSha256": None, "lastOutcome": None}
        authority = {"bundleSha256": "e" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, old_request, "f" * 64, 42, authority)), \
                 patch.object(successor, "_inspect", side_effect=[{"state": "closed", "record": old}, {"state": "active", "record": new}]), \
                 patch.object(successor, "_remote_marker_clean", return_value=True), \
                 patch.object(successor.base, "_campaign_remote", return_value=object()), \
                 patch.object(successor.campaign_status, "_remote_closed_proof", return_value=False):
                result = successor.status(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])

    def test_causal_regression_status_blocks_when_exact_remote_abort_marker_is_missing(self):
        old_request = self._old_request()
        old_identity = successor.base._campaign_identity({**old_request, "correlationId": successor._OLD}, DESC)
        new_identity = successor.base._campaign_identity({**old_request, "correlationId": NEW}, DESC)
        old = {"identity": old_identity, "state": "closed", "role": None, "correlationId": None, "server": "stopped", "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": successor._cleanup(DESC, "f" * 64)["cleanupReceiptSha256"]}
        new = {"identity": new_identity, "state": "active", "role": None, "correlationId": None, "server": "stopped", "credentials": "absent", "sequence": 0, "lastEvidenceSha256": None, "lastOutcome": None}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, old_request, "f" * 64, 42, {"bundleSha256": "e" * 64})), \
                 patch.object(successor, "_inspect", side_effect=[{"state": "closed", "record": old}, {"state": "active", "record": new}]), \
                 patch.object(successor, "_remote_marker_clean", return_value=False), \
                 patch.object(successor.campaign_status, "_remote_closed_proof", return_value=True):
                result = successor.status(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])

    def test_causal_regression_reconcile_blocks_when_remote_abort_marker_is_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            binding = (object(), object(), DESC, self._old_request(), "f" * 64, 42, {"bundleSha256": "e" * 64})
            with patch.object(successor, "_receipt_binding", return_value=binding), \
                 patch.object(successor, "_idle", return_value=True), \
                 patch.object(successor, "_remote_marker_clean", return_value=False), \
                 patch.object(successor.lease, "inspect") as inspect, \
                 patch.object(successor.lease, "reconcile") as reconcile:
                result = successor.reconcile(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        inspect.assert_not_called(); reconcile.assert_not_called()

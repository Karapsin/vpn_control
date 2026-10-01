"""Causal checks for the one retired lost-download campaign successor."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_tools import windows_cp117_download_abort_successor as successor


NEW = "d1387ac6-bd49-470b-9e8d-399a44760329"
ARTIFACTS = {"fixtureReceiptArtifactId": "sha256-" + "a" * 64,
             "baseMsiArtifactId": "sha256-" + "b" * 64,
             "targetMsiArtifactId": "sha256-" + "c" * 64}
REQUEST = {"host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": NEW,
           "sourceSha": successor._SOURCE, **ARTIFACTS}
DESC = ("windows-cp117", "/qga", 20241, 98231, "S-1-5-21-1-2-3-1002")


class DownloadAbortSuccessorTest(unittest.TestCase):
    def _old_request(self):
        return {"correlationId": successor._CORRELATION, "sourceSha": successor._SOURCE, **ARTIFACTS}

    def _receipt(self):
        value = {"correlationId": successor._CORRELATION, "leaseId": successor._OLD,
                 "sourceSha": successor._SOURCE, "bundleSha256": "e" * 64,
                 "sourceFingerprint": "d" * 64,
                 "guestGeneration": {"socketPath": DESC[1], "qemuPid": DESC[2], "startTicks": DESC[3]},
                 "listener": "stopped-unserved", "guestLeaf": "retained-empty-created",
                 "task": "absent", "runtimeAndInstaller": "absent"}
        return value, successor._digest(value)

    def _active(self, digest):
        return {"identity": successor.base._campaign_identity({**self._old_request(), "correlationId": successor._OLD}, DESC),
                "state": "active", "role": None, "correlationId": None, "server": "stopped",
                "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": digest}

    def _admission_patches(self, temporary):
        receipt, digest = self._receipt()
        record = {"leaseId": successor._OLD, "request": self._old_request(),
                  "sourceFingerprint": "d" * 64, "bundleSha256": "e" * 64, "bundleSize": 42}
        target = SimpleNamespace(fixture_transfer_root="/transfer")
        return (patch.object(successor.abort, "_admission", return_value=("retired", (Path(temporary), record, object(), target, DESC, receipt, digest))),
                patch.object(successor.lease, "_locked", return_value=(Path(temporary), 0)),
                patch.object(successor.os, "close"), patch.object(successor.lease, "_active", return_value=self._active(digest)),
                patch.object(successor, "_idle", return_value=True), patch.object(successor, "_remote_marker_clean", return_value=True),
                patch.object(successor.lease, "_remote_confirm", return_value=True), receipt, digest)

    def test_exact_retired_download_abort_closes_then_reserves_distinct_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            patches = self._admission_patches(temporary)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
                 patch.object(successor.lease, "close", return_value={"state": "closed"}) as close, \
                 patch.object(successor.lease, "begin", return_value={"state": "active"}) as begin:
                result = successor.start(temporary, REQUEST)
        self.assertEqual({"state": "active", "leaseId": NEW, "replayAllowed": False, "nativeActionAllowed": False}, result)
        self.assertEqual(successor._OLD, close.call_args.args[1])
        self.assertEqual(NEW, begin.call_args.args[1]["leaseId"])

    def test_causal_regression_changed_retained_empty_proof_blocks_before_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            patches = self._admission_patches(temporary); receipt, digest = self._receipt(); receipt["guestLeaf"] = "removed"
            record = {"leaseId": successor._OLD, "request": self._old_request(), "sourceFingerprint": "d" * 64, "bundleSha256": "e" * 64, "bundleSize": 42}
            bad = (Path(temporary), record, object(), SimpleNamespace(fixture_transfer_root="/transfer"), DESC, receipt, successor._digest(receipt))
            with patch.object(successor.abort, "_admission", return_value=("retired", bad)), patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(successor.lease, "close") as close:
                result = successor.start(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        close.assert_not_called()

    def test_causal_regression_request_cannot_change_source_or_old_lease(self):
        changed = dict(REQUEST); changed["sourceSha"] = "f" * 40
        with self.assertRaises(successor.WindowsCp117DownloadAbortSuccessorError): successor._request(changed)
        changed = dict(REQUEST); changed["oldLeaseId"] = "00000000-0000-4000-8000-000000000000"
        with self.assertRaises(successor.WindowsCp117DownloadAbortSuccessorError): successor._request(changed)

    def test_reconcile_is_read_only_when_abort_marker_is_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            binding = (object(), object(), DESC, self._old_request(), "f" * 64, 42, {"bundleSha256": "e" * 64})
            with patch.object(successor, "_receipt_binding", return_value=binding), patch.object(successor, "_idle", return_value=True), patch.object(successor, "_remote_marker_clean", return_value=False), patch.object(successor.lease, "close") as close, patch.object(successor.lease, "begin") as begin:
                result = successor.reconcile(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        close.assert_not_called(); begin.assert_not_called()

    def test_resume_begin_requires_durable_intent_before_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", side_effect=successor.WindowsCp117DownloadAbortSuccessorError()), patch.object(successor.lease, "begin") as begin:
                result = successor.resume_begin(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        begin.assert_not_called()

    def test_resume_close_consumes_saved_intent_but_does_not_open_new_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt, digest = self._receipt(); target = SimpleNamespace(fixture_transfer_root="/transfer")
            binding = (object(), target, DESC, self._old_request(), digest, 42,
                       {"bundleSha256": "e" * 64})
            active = self._active(digest)
            admitted = (object(), target, DESC, self._old_request(), receipt, digest, active, 42,
                        {"bundleSha256": "e" * 64})
            with patch.object(successor, "_receipt_binding", return_value=binding), patch.object(successor, "_admission", return_value=admitted), patch.object(successor.base, "_campaign_remote", return_value=object()), patch.object(successor.lease, "close", return_value={"state": "closed"}) as close, patch.object(successor.lease, "begin") as begin:
                result = successor.resume_close(temporary, REQUEST)
        self.assertEqual({"state": "closed", "leaseId": NEW, "replayAllowed": False, "nativeActionAllowed": False}, result)
        self.assertEqual(successor._OLD, close.call_args.args[1])
        begin.assert_not_called()

    def test_resume_close_rejects_changed_fresh_abort_receipt_before_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt, digest = self._receipt(); receipt["guestLeaf"] = "changed"; target = SimpleNamespace(fixture_transfer_root="/transfer")
            binding = (object(), target, DESC, self._old_request(), digest, 42, {"bundleSha256": "e" * 64})
            admitted = (object(), target, DESC, self._old_request(), receipt, successor._digest(receipt), self._active(digest), 42, {"bundleSha256": "e" * 64})
            with patch.object(successor, "_receipt_binding", return_value=binding), patch.object(successor, "_admission", return_value=admitted), patch.object(successor.lease, "close") as close:
                result = successor.resume_close(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        close.assert_not_called()

    def test_status_rejects_closed_local_campaign_without_remote_closed_proof(self):
        old_request = self._old_request(); old_identity = successor.base._campaign_identity({**old_request, "correlationId": successor._OLD}, DESC); new_identity = successor.base._campaign_identity({**old_request, "correlationId": NEW}, DESC)
        old = {"identity": old_identity, "state": "closed", "role": None, "correlationId": None, "server": "stopped", "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": successor._cleanup(DESC, "f" * 64)["cleanupReceiptSha256"]}
        new = {"identity": new_identity, "state": "active", "role": None, "correlationId": None, "server": "stopped", "credentials": "absent", "sequence": 0, "lastEvidenceSha256": None, "lastOutcome": None}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, old_request, "f" * 64, 42, {"bundleSha256": "e" * 64})), patch.object(successor, "_inspect", side_effect=[{"state": "closed", "record": old}, {"state": "active", "record": new}]), patch.object(successor, "_retained_empty_guest", return_value=True), patch.object(successor, "_remote_marker_clean", return_value=True), patch.object(successor.campaign_status, "_remote_closed_proof", return_value=False):
                result = successor.status(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])

    def test_status_reports_pending_close_without_replaying_or_opening(self):
        old_request = self._old_request()
        old = {"identity": successor.base._campaign_identity({**old_request, "correlationId": successor._OLD}, DESC),
               "state": "pending-close", "role": None, "correlationId": None, "server": "stopped",
               "credentials": "absent", "lastOutcome": "failed-cleaned",
               "lastEvidenceSha256": successor._cleanup(DESC, "f" * 64)["cleanupReceiptSha256"]}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, old_request, "f" * 64, 42, {"bundleSha256": "e" * 64})), patch.object(successor, "_inspect", side_effect=[{"state": "pending-close", "record": old}, {"state": "unknown", "record": None}]), patch.object(successor, "_retained_empty_guest", return_value=True), patch.object(successor, "_remote_marker_clean", return_value=True), patch.object(successor.lease, "_remote_confirm", side_effect=AssertionError("reconcile owns pending close")):
                result = successor.status(temporary, REQUEST)
        self.assertEqual("closing", result["state"])
        self.assertEqual("inspect-close-progress", result["nextAction"])

    def test_status_directs_saved_but_unclosed_intent_to_resume_close_without_mutation(self):
        old_request = self._old_request()
        old = {"identity": successor.base._campaign_identity({**old_request, "correlationId": successor._OLD}, DESC),
               "state": "active", "role": None, "correlationId": None, "server": "stopped",
               "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": "f" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, old_request, "f" * 64, 42, {"bundleSha256": "e" * 64})), patch.object(successor, "_inspect", side_effect=[{"state": "active", "record": old}, {"state": "unknown", "record": None}]), patch.object(successor, "_retained_empty_guest", return_value=True), patch.object(successor, "_remote_marker_clean", return_value=True), patch.object(successor.base, "_campaign_remote", return_value=object()), patch.object(successor.lease, "_remote_confirm", return_value=True), patch.object(successor.lease, "close") as close, patch.object(successor.lease, "begin") as begin:
                result = successor.status(temporary, REQUEST)
        self.assertEqual("closing", result["state"])
        self.assertEqual("resume-close", result["nextAction"])
        close.assert_not_called(); begin.assert_not_called()

    def test_status_blocks_when_retained_empty_guest_proof_changes(self):
        old_request = self._old_request()
        old = {"identity": successor.base._campaign_identity({**old_request, "correlationId": successor._OLD}, DESC),
               "state": "active", "role": None, "correlationId": None, "server": "stopped",
               "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": "f" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, old_request, "f" * 64, 42, {"bundleSha256": "e" * 64})), patch.object(successor, "_inspect", side_effect=[{"state": "active", "record": old}, {"state": "unknown", "record": None}]), patch.object(successor, "_retained_empty_guest", return_value=False), patch.object(successor, "_remote_marker_clean", side_effect=AssertionError("must not trust host marker")):
                result = successor.status(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])

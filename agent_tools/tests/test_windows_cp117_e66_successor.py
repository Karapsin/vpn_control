"""Causal regressions for the one retired-e66 successor admission."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_cp117_e66_successor as successor


OLD = successor._OLD
NEW = "c32cb108-4d48-407e-9153-40774559ba50"
SOURCE = "a" * 40
ARTIFACTS = {"fixtureReceiptArtifactId": "sha256-" + "b" * 64,
             "baseMsiArtifactId": "sha256-" + "c" * 64,
             "targetMsiArtifactId": "sha256-" + "d" * 64}
REQUEST = {"host": "archlinux", "oldLeaseId": OLD, "newLeaseId": NEW, "sourceSha": SOURCE, **ARTIFACTS}
DESC = ("windows-cp117", "/qga", 589342, 520739, "S-1-5-21-1-2-3-1002")
RETIRED = "8" * 64


class E66SuccessorTest(unittest.TestCase):
    def _record(self):
        return {"request": {"correlationId": successor.e66._E66_CORRELATION, "sourceSha": SOURCE, **ARTIFACTS}}

    def _retirement(self):
        receipt = {"correlationId": successor.e66._E66_CORRELATION, "leaseId": OLD,
                   "sourceFingerprint": "1" * 64, "bundleSha256": "2" * 64,
                   "guestGeneration": {"socketPath": DESC[1], "qemuPid": DESC[2], "startTicks": DESC[3]},
                   "transcriptSha256": "3" * 64, "coreSha256": "4" * 64,
                   "remoteStage": "absent", "remoteCampaign": "confirmed"}
        return receipt, successor._digest(receipt)

    def _active(self, retired=RETIRED):
        identity = successor.base._campaign_identity({**self._record()["request"], "correlationId": OLD}, DESC)
        return {"identity": identity, "state": "active", "role": None, "correlationId": None,
                "server": "stopped", "credentials": "absent", "lastOutcome": "failed-cleaned",
                "lastEvidenceSha256": retired}

    def _admitted(self, temporary):
        receipt, retired = self._retirement()
        return (patch.object(successor.e66, "_e66_retirement_admission",
                             return_value=("retired", (Path(temporary), self._record(), object(), object(), object(), receipt, retired))),
                patch.object(successor.base, "_descriptor", return_value=(object(), object(), DESC)),
                patch.object(successor.lease, "_locked", return_value=(Path(temporary), 0)),
                patch.object(successor.os, "close"), patch.object(successor.lease, "_active", return_value=self._active(retired)),
                patch.object(successor, "_idle", return_value=True))

    def test_retired_e66_can_close_then_open_one_distinct_same_artifact_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            patches = self._admitted(temporary)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                 patch.object(successor.lease, "close", return_value={"state": "closed"}) as close, \
                 patch.object(successor.lease, "begin", return_value={"state": "active"}) as begin:
                result = successor.start(temporary, REQUEST)
        self.assertEqual({"state": "active", "leaseId": NEW, "replayAllowed": False, "nativeActionAllowed": False}, result)
        self.assertEqual(OLD, close.call_args.args[1])
        self.assertEqual(NEW, begin.call_args.args[1]["leaseId"])
        self.assertEqual(SOURCE, begin.call_args.args[1]["sourceSha"])

    def test_causal_regression_generic_history_rejects_shared_old_lease_but_fixed_successor_does_not_call_it(self):
        """The former route rejects e66 because its old lease is the active lease."""
        with tempfile.TemporaryDirectory() as temporary:
            patches = self._admitted(temporary)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                 patch.object(successor.e66.stage, "_closed_stage_history_detail", side_effect=AssertionError("generic history is forbidden")), \
                 patch.object(successor.lease, "close", return_value={"state": "closed"}), \
                 patch.object(successor.lease, "begin", return_value={"state": "active"}):
                self.assertEqual("active", successor.start(temporary, REQUEST)["state"])

    def test_changed_artifact_or_retirement_evidence_blocks_before_close(self):
        for request, active in (({**REQUEST, "targetMsiArtifactId": "sha256-" + "9" * 64}, self._active()),
                                (REQUEST, {**self._active(), "lastEvidenceSha256": "9" * 64})):
            with self.subTest(request=request["targetMsiArtifactId"][-1], evidence=active["lastEvidenceSha256"][-1]), tempfile.TemporaryDirectory() as temporary:
                patches = list(self._admitted(temporary)); patches[4] = patch.object(successor.lease, "_active", return_value=active)
                with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                     patch.object(successor.lease, "close") as close:
                    self.assertEqual("unknown", successor.start(temporary, request)["state"])
                close.assert_not_called()

    def test_owner_or_guest_not_idle_blocks_before_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            patches = list(self._admitted(temporary)); patches[5] = patch.object(successor, "_idle", return_value=False)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patch.object(successor.lease, "close") as close:
                self.assertEqual("unknown", successor.start(temporary, REQUEST)["state"])
            close.assert_not_called()

    def test_partial_close_is_read_only_status_and_does_not_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor, "_inspect_readonly", side_effect=[{"state": "active", "record": self._active()}, {"state": "unknown"}]):
                observed = successor.status(root, REQUEST)
        self.assertEqual("closing", observed["state"])
        self.assertFalse(observed["replayAllowed"])

    def test_status_missing_receipts_creates_no_campaign_or_successor_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual("unknown", successor.status(root, REQUEST)["state"])
            self.assertFalse((root / successor._DIR).exists())
            self.assertFalse((root / successor.lease._DIR).exists())

    def test_reconcile_reads_back_pending_open_without_calling_close_or_begin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = successor.base._campaign_identity({**self._record()["request"], "correlationId": NEW}, DESC)
            initial = {"identity": identity, "state": "active", "role": None, "correlationId": None,
                       "server": "stopped", "credentials": "absent", "sequence": 0,
                       "lastEvidenceSha256": None, "lastOutcome": None}
            old_closed = {**self._active(), "lastEvidenceSha256": successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"]}
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor, "_idle", return_value=True), \
                 patch.object(successor.lease, "inspect", side_effect=[{"state": "closed"}, {"state": "pending-remote"}]), \
                 patch.object(successor.campaign_status, "_remote_closed_proof", return_value=True), \
                 patch.object(successor.lease, "reconcile", return_value={"state": "active"}) as reconcile, \
                 patch.object(successor, "_inspect_readonly", side_effect=[{"state": "closed", "record": old_closed}, {"state": "active", "record": initial}]), \
                 patch.object(successor.lease, "close", side_effect=AssertionError("no replay")), \
                 patch.object(successor.lease, "begin", side_effect=AssertionError("no replay")):
                result = successor.reconcile(root, REQUEST)
        self.assertEqual("active", result["state"])
        reconcile.assert_called_once()

    def test_start_passes_exact_retired_active_record_to_close_cas(self):
        with tempfile.TemporaryDirectory() as temporary:
            patches = self._admitted(temporary)
            old = self._active(self._retirement()[1])
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                 patch.object(successor.lease, "close", return_value={"state": "unknown"}) as close, \
                 patch.object(successor.lease, "begin") as begin:
                self.assertEqual("unknown", successor.start(temporary, REQUEST)["state"])
        self.assertEqual(old, close.call_args.kwargs["expected_current"])
        begin.assert_not_called()

    def test_status_rejects_role_active_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = {**self._active(), "lastEvidenceSha256": successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"]}
            role_active = {"identity": successor.base._campaign_identity({**self._record()["request"], "correlationId": NEW}, DESC),
                           "state": "role-active", "role": "stage", "correlationId": successor.e66._E66_CORRELATION,
                           "server": "stopped", "credentials": "absent", "sequence": 1,
                           "lastEvidenceSha256": None, "lastOutcome": None}
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor, "_inspect_readonly", side_effect=[{"state": "closed", "record": old}, {"state": "role-active", "record": role_active}]):
                self.assertEqual("unknown", successor.status(root, REQUEST)["state"])

    def test_reconcile_rejects_role_active_successor_after_readback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_closed = {**self._active(), "lastEvidenceSha256": successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"]}
            role_active = {"identity": successor.base._campaign_identity({**self._record()["request"], "correlationId": NEW}, DESC),
                           "state": "role-active", "role": "stage", "correlationId": successor.e66._E66_CORRELATION,
                           "server": "stopped", "credentials": "absent", "sequence": 1,
                           "lastEvidenceSha256": None, "lastOutcome": None}
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor, "_idle", return_value=True), \
                 patch.object(successor.lease, "inspect", side_effect=[{"state": "closed"}, {"state": "pending-remote"}]), \
                 patch.object(successor.campaign_status, "_remote_closed_proof", return_value=True), \
                 patch.object(successor.lease, "reconcile", return_value={"state": "active"}), \
                 patch.object(successor, "_inspect_readonly", side_effect=[{"state": "closed", "record": old_closed}, {"state": "role-active", "record": role_active}]):
                self.assertEqual("unknown", successor.reconcile(root, REQUEST)["state"])

    def test_resume_begin_recovers_closed_before_begin_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); journal = root / successor._DIR; journal.mkdir(parents=True, mode=0o700)
            identity = successor.base._campaign_identity({**self._record()["request"], "correlationId": OLD}, DESC)
            closed = {"identity": identity, "role": None, "correlationId": None, "server": "stopped",
                      "credentials": "absent", "lastOutcome": "failed-cleaned",
                      "lastEvidenceSha256": successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"]}
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor.lease, "_locked", side_effect=lambda _root: (root, successor.os.open(root / ".campaign.lock", successor.os.O_RDWR | successor.os.O_CREAT, 0o600))), \
                 patch.object(successor.lease, "_active", return_value=None), patch.object(successor.lease, "_closed", return_value=closed), \
                 patch.object(successor.lease, "_remote_confirm", return_value=True), patch.object(successor, "_remote_new_absent", return_value=True), \
                 patch.object(successor, "_idle", return_value=True), patch.object(successor.lease, "begin", return_value={"state": "active"}) as begin:
                self.assertEqual("active", successor.resume_begin(root, REQUEST)["state"])
                self.assertTrue((journal / (NEW + ".begin.json")).exists())
        begin.assert_called_once()

    def test_resume_begin_reuses_exact_marker_only_when_new_is_still_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); journal = root / successor._DIR; journal.mkdir(parents=True, mode=0o700)
            cleanup = successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"]
            marker = journal / (NEW + ".begin.json")
            marker.write_text('{"newLeaseId":"' + NEW + '","oldCleanupReceiptSha256":"' + cleanup + '","version":1}\n'); marker.chmod(0o600)
            identity = successor.base._campaign_identity({**self._record()["request"], "correlationId": OLD}, DESC)
            closed = {"identity": identity, "role": None, "correlationId": None, "server": "stopped",
                      "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": cleanup}
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor.lease, "_locked", side_effect=lambda _root: (root, successor.os.open(root / ".campaign.lock", successor.os.O_RDWR | successor.os.O_CREAT, 0o600))), \
                 patch.object(successor.lease, "_active", return_value=None), patch.object(successor.lease, "_closed", return_value=closed), \
                 patch.object(successor.lease, "_remote_confirm", return_value=True), patch.object(successor, "_remote_new_absent", return_value=True), \
                 patch.object(successor, "_idle", return_value=True), patch.object(successor.lease, "begin", return_value={"state": "active"}) as begin:
                self.assertEqual("active", successor.resume_begin(root, REQUEST)["state"])
            begin.assert_called_once()

    def test_resume_begin_never_replays_when_new_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), patch.object(successor.lease, "_locked", return_value=(root, successor.os.open(root / ".campaign.lock", successor.os.O_RDWR | successor.os.O_CREAT, 0o600))), \
                 patch.object(successor.lease, "_active", return_value={"state": "pending-remote"}), patch.object(successor.lease, "begin") as begin:
                self.assertEqual("unknown", successor.resume_begin(root, REQUEST)["state"])
            begin.assert_not_called()

    def test_idle_uses_literal_version_explorer_and_dormant_owner_leaf(self):
        ready = {"state": "ready", "ready": True, "code": "READY", "productCount": 1, "activeCount": 0,
                 "activeProcesses": [], "workspaceLockPid": 777, "ownedExplorerCount": 1}
        owner = {"state": "blocked", "ownerProcesses": "none", "installerProcesses": "none",
                 "consentProcesses": "none", "runtimeProcesses": "none", "runtimeOff": True, "stateLeaves": "one"}
        with patch.object(successor.base, "readiness", return_value=ready) as readiness, \
             patch.object(successor.owner_liveness, "observe", return_value=owner):
            self.assertTrue(successor._idle(Path.cwd()))
        self.assertEqual("2.1.19", readiness.call_args.args[1]["expectedCurrentVersion"])

    def test_status_rejects_malformed_receipt_and_unrelated_active_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); journal = root / successor._DIR; journal.mkdir(parents=True, mode=0o700)
            path = journal / (NEW + ".json"); path.write_text('{"version":1}'); path.chmod(0o600)
            with patch.object(successor.base, "_descriptor", return_value=(object(), object(), DESC)):
                self.assertEqual("unknown", successor.status(root, REQUEST)["state"])
            wrong = {"identity": {"leaseId": NEW, "sourceSha": "f" * 40}}
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor, "_inspect_readonly", side_effect=[{"state": "closed"}, {"state": "active", "record": wrong}]):
                self.assertEqual("unknown", successor.status(root, REQUEST)["state"])

    def test_status_does_not_project_closing_for_unrelated_old_active_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unrelated = {"identity": {"leaseId": OLD, "sourceSha": "f" * 40}, "role": None,
                         "correlationId": None, "server": "stopped", "credentials": "absent",
                         "lastOutcome": "failed-cleaned", "lastEvidenceSha256": RETIRED}
            with patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, self._record()["request"], RETIRED)), \
                 patch.object(successor, "_inspect_readonly", side_effect=[{"state": "active", "record": unrelated}, {"state": "unknown"}]):
                self.assertEqual("unknown", successor.status(root, REQUEST)["state"])

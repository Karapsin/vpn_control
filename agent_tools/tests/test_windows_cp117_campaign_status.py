"""Causal tests for the read-only CP117 campaign status observer."""
from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from agent_tools import windows_cp117_campaign_status as status


SOURCE = "a" * 40
LEASE = "c32cb108-4d48-407e-9153-40774559ba50"
NEW_LEASE = "f90c0284-bb5a-4ed4-a2ef-3d870746a322"
DESCRIPTOR = ("windows-cp117", "/qga", 589342, 520739, "S-1-5-21-1-2-3-1002")
IDENTITY = {"host": "archlinux", "environment": "windows-cp117", "leaseId": LEASE,
            "operator": "windows-base", "sourceSha": SOURCE,
            "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
            "baseMsiArtifactId": "sha256-" + "c" * 64,
            "targetMsiArtifactId": "sha256-" + "d" * 64,
            "socketPath": "/qga", "qemuPid": 589342, "startTicks": 520739}
RECORD = {"version": 1, "identity": IDENTITY, "sequence": 3, "state": "role-active", "role": "stage",
          "correlationId": "7f270b5d-5bf7-42d2-b6be-909f6b3ef945", "server": "stopped", "credentials": "absent",
          "lastEvidenceSha256": "e" * 64, "lastOutcome": "succeeded"}
REQUEST = {"correlationId": LEASE, "sourceSha": SOURCE, "fixtureReceiptArtifactId": IDENTITY["fixtureReceiptArtifactId"],
           "baseMsiArtifactId": IDENTITY["baseMsiArtifactId"], "targetMsiArtifactId": IDENTITY["targetMsiArtifactId"]}
PAIR = {"sourceSha": SOURCE, "baseVersion": "2.1.19"}
IDLE = {"state": "ready", "ready": True, "installedVersion": "2.1.19", "productCount": 1,
        "activeCount": 0, "activeProcesses": []}


class CampaignStatusTest(unittest.TestCase):
    def _patches(self, record=RECORD):
        intent = {"request": REQUEST}
        return (patch.object(status.lease, "_active", return_value=record),
                patch.object(status.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)),
                patch.object(status.base, "_private_intent", return_value=intent),
                patch.object(status.base, "_request", return_value=REQUEST),
                patch.object(status.base, "_stage_artifact_readonly", return_value=(PAIR, None)),
                patch.object(status.base, "_campaign_identity", return_value=IDENTITY),
                patch.object(status.base, "_campaign_remote", return_value=object()),
                patch.object(status.lease, "_remote_confirm", return_value=True),
                patch.object(status.base, "readiness", return_value=IDLE))

    def _root(self):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        directory = root / status.lease._DIR; directory.mkdir(parents=True, mode=0o700)
        return temporary, root

    def test_role_active_is_green_only_after_exact_remote_and_idle_base(self):
        temporary, root = self._root()
        with temporary, self._patches()[0], self._patches()[1], self._patches()[2], self._patches()[3], self._patches()[4], self._patches()[5], self._patches()[6], self._patches()[7], self._patches()[8]:
            observed = status.status(root, {"host": "archlinux"})
        self.assertEqual("active", observed["state"])
        self.assertEqual("stage", observed["role"])
        self.assertFalse(observed["nativeActionAllowed"])
        self.assertFalse(observed["replayAllowed"])

    def test_partial_close_is_closing_without_remote_confirmation(self):
        closing = {**RECORD, "state": "pending-close", "role": None, "correlationId": None}
        temporary, root = self._root()
        patches = self._patches(closing)
        with temporary, ExitStack() as stack:
            for item in patches: stack.enter_context(item)
            observed = status.status(root, {"host": "archlinux"})
        self.assertEqual({"state": "closing", "nextAction": "inspect-close-progress"},
                         {key: observed[key] for key in ("state", "nextAction")})

    def test_generation_or_artifact_mismatch_stays_red_unknown(self):
        temporary, root = self._root()
        patches = list(self._patches())
        patches[5] = patch.object(status.base, "_campaign_identity", return_value={**IDENTITY, "startTicks": 1})
        with temporary, ExitStack() as stack:
            for item in patches: stack.enter_context(item)
            observed = status.status(root, {"host": "archlinux"})
        self.assertEqual("unknown", observed["state"])
        self.assertEqual("inspect-prerequisites", observed["nextAction"])

    def test_missing_journal_is_a_finite_missing_prerequisite(self):
        with tempfile.TemporaryDirectory() as temporary:
            observed = status.status(temporary, {"host": "archlinux"})
        self.assertEqual({"state": "unknown", "nextAction": "missing-prerequisite"},
                         {key: observed[key] for key in ("state", "nextAction")})

    def test_confirmed_closed_campaign_is_green_only_after_remote_and_idle_proof(self):
        closed = {**RECORD, "state": "closed", "role": None, "correlationId": None,
                  "credentials": "cleaned"}
        temporary, root = self._root()
        patches = list(self._patches())
        patches[0] = patch.object(status.lease, "_active", return_value=None)
        with temporary, ExitStack() as stack:
            for item in patches: stack.enter_context(item)
            with patch.object(status, "_bound_closed", return_value=(closed, PAIR)):
                observed = status.status(root, {"host": "archlinux"})
        self.assertEqual({"state": "closed", "nextAction": "inspect-closed-campaign"},
                         {key: observed[key] for key in ("state", "nextAction")})

    def test_closed_old_campaign_and_exact_active_rebase_bind_green(self):
        """Regression: status must follow the verified successor lease, not only base intent."""
        temporary, root = self._root()
        new_identity = {**IDENTITY, "leaseId": NEW_LEASE}
        new_record = {**RECORD, "identity": new_identity, "state": "active", "role": None,
                      "correlationId": None}
        request = {"host": "archlinux", "leaseId": NEW_LEASE, "previousLeaseId": LEASE,
                   "sourceSha": SOURCE, "fixtureReceiptArtifactId": IDENTITY["fixtureReceiptArtifactId"],
                   "baseMsiArtifactId": IDENTITY["baseMsiArtifactId"], "targetMsiArtifactId": IDENTITY["targetMsiArtifactId"]}
        old_closed = {**RECORD, "state": "closed", "role": None, "correlationId": None,
                      "credentials": "absent", "identity": IDENTITY, "lastOutcome": "failed-cleaned",
                      "lastEvidenceSha256": "8" * 64}
        with temporary:
            journal = root / status.rebase._DIR; journal.mkdir(mode=0o700)
            (journal / (NEW_LEASE + ".json")).write_text(json.dumps({"version": 1, "request": request,
                "previousStageCorrelationId": status.rebase.recovery._CORRELATION, "previousLeaseId": LEASE,
                "baseTerminalReceiptSha256": "f" * 64,
                "guestGeneration": {"socketPath": "/qga", "qemuPid": 589342, "startTicks": 520739},
                "sourceFingerprint": "9" * 64}) + "\n")
            (journal / (NEW_LEASE + ".json")).chmod(0o600)
            def identity_for(value, _descriptor):
                return {**IDENTITY, "leaseId": value["correlationId"]}
            with patch.object(status.rebase, "_history", return_value=({"old": True}, {**PAIR, "sourceFingerprint": "9" * 64}, "f" * 64, "8" * 64)), \
                 patch.object(status.base, "_campaign_identity", side_effect=identity_for), \
                 patch.object(status.lease, "_closed", return_value=old_closed), \
                 patch.object(status.base, "_campaign_remote", return_value=object()), \
                 patch.object(status, "_remote_closed_proof", return_value=True):
                bound = status._rebase_binding(root, new_record, DESCRIPTOR, object(), object())
        self.assertIsNotNone(bound)
        self.assertEqual("2.1.19", bound[1]["baseVersion"])

    def test_rebase_rejects_old_close_without_exact_cleanup_evidence(self):
        temporary, root = self._root()
        new_identity = {**IDENTITY, "leaseId": NEW_LEASE}
        new_record = {**RECORD, "identity": new_identity, "state": "active", "role": None,
                      "correlationId": None}
        request = {"host": "archlinux", "leaseId": NEW_LEASE, "previousLeaseId": LEASE,
                   "sourceSha": SOURCE, "fixtureReceiptArtifactId": IDENTITY["fixtureReceiptArtifactId"],
                   "baseMsiArtifactId": IDENTITY["baseMsiArtifactId"], "targetMsiArtifactId": IDENTITY["targetMsiArtifactId"]}
        old_closed = {**RECORD, "state": "closed", "role": None, "correlationId": None,
                      "credentials": "absent", "identity": IDENTITY, "lastOutcome": "failed-cleaned",
                      "lastEvidenceSha256": "wrong"}
        with temporary:
            journal = root / status.rebase._DIR; journal.mkdir(mode=0o700)
            (journal / (NEW_LEASE + ".json")).write_text(json.dumps({"version": 1, "request": request,
                "previousStageCorrelationId": status.rebase.recovery._CORRELATION, "previousLeaseId": LEASE,
                "baseTerminalReceiptSha256": "f" * 64,
                "guestGeneration": {"socketPath": "/qga", "qemuPid": 589342, "startTicks": 520739},
                "sourceFingerprint": "9" * 64}) + "\n")
            (journal / (NEW_LEASE + ".json")).chmod(0o600)
            with patch.object(status.rebase, "_history", return_value=({"old": True}, {**PAIR, "sourceFingerprint": "9" * 64}, "f" * 64, "8" * 64)), \
                 patch.object(status.base, "_campaign_identity", side_effect=lambda value, _: {**IDENTITY, "leaseId": value["correlationId"]}), \
                 patch.object(status.lease, "_closed", return_value=old_closed), \
                 patch.object(status.base, "_campaign_remote", return_value=object()), \
                 patch.object(status, "_remote_closed_proof", return_value=True):
                bound = status._rebase_binding(root, new_record, DESCRIPTOR, object(), object())
        self.assertIsNone(bound)

    def test_rebase_predecessor_proof_does_not_use_closed_status_when_new_lease_is_active(self):
        """Regression: CP117's ordinary closed status rejects a valid successor active record."""
        closed = {**RECORD, "state": "closed", "role": None, "correlationId": None,
                  "credentials": "absent", "lastOutcome": "failed-cleaned"}
        expected = {"version": 1, "state": "confirmed",
                    "closedSha256": __import__("hashlib").sha256(json.dumps(closed, sort_keys=True,
                                                                               separators=(",", ":")).encode()).hexdigest()}
        with patch.object(status.base, "_remote", return_value=json.dumps(expected).encode()) as remote, \
             patch.object(status.lease, "_remote_confirm", side_effect=AssertionError("ordinary status is unsafe")):
            self.assertTrue(status._remote_closed_proof(object(), type("Target", (), {"fixture_transfer_root": "/owned"})(),
                                                        closed, {**IDENTITY, "leaseId": NEW_LEASE}))
        self.assertEqual(status._REMOTE_CLOSED_PROOF, remote.call_args.args[1])

    def test_rebase_partial_close_remains_closing_after_successor_binding(self):
        closing = {**RECORD, "identity": {**IDENTITY, "leaseId": NEW_LEASE}, "state": "pending-close",
                   "role": None, "correlationId": None}
        temporary, root = self._root()
        with temporary, \
             patch.object(status.lease, "_active", return_value=closing), \
             patch.object(status.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
             patch.object(status, "_base_binding", return_value=None), \
             patch.object(status, "_rebase_binding", return_value=({"old": True}, PAIR)):
            observed = status.status(root, {"host": "archlinux"})
        self.assertEqual("closing", observed["state"])
        self.assertFalse(observed["nativeActionAllowed"])

    def test_current_download_abort_successor_binds_only_its_immutable_receipt_and_closed_predecessor(self):
        """Regression: the isolated current successor must not appear as an unknown campaign."""
        from agent_tools import windows_cp117_download_abort_current_successor as successor

        temporary, root = self._root()
        new_lease = "e59a7483-4e38-4e7b-b8fa-0d8b2356916a"
        new_identity = {**IDENTITY, "leaseId": new_lease, "sourceSha": successor._SOURCE}
        new_record = {**RECORD, "identity": new_identity, "state": "active", "role": None,
                      "correlationId": None}
        request = {"host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": new_lease,
                   "sourceSha": successor._SOURCE,
                   "fixtureReceiptArtifactId": IDENTITY["fixtureReceiptArtifactId"],
                   "baseMsiArtifactId": IDENTITY["baseMsiArtifactId"],
                   "targetMsiArtifactId": IDENTITY["targetMsiArtifactId"]}
        old_request = {"correlationId": successor._CORRELATION, "sourceSha": successor._SOURCE,
                       **{key: request[key] for key in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId")}}
        stored = {"request": request, "abortReceipt": {"sourceFingerprint": "current-fingerprint"}}
        old = {**RECORD, "state": "closed", "role": None, "correlationId": None,
               "identity": {**IDENTITY, "leaseId": successor._OLD, "sourceSha": successor._SOURCE},
               "lastOutcome": "failed-cleaned", "lastEvidenceSha256": "cleanup",
               "server": "stopped", "credentials": "absent"}
        impl = successor._impl
        def campaign_identity(value, _descriptor):
            return {**IDENTITY, "leaseId": value["correlationId"], "sourceSha": successor._SOURCE}
        with temporary, \
             patch.object(impl, "_journal", return_value=root), \
             patch.object(impl, "_read", return_value=stored), \
             patch.object(impl, "_receipt_binding", return_value=(object(), object(), DESCRIPTOR, old_request, "retired", 42, {"bundleSha256": "bundle"})), \
             patch.object(impl.abort, "_retired_binding", return_value=(root, {"request": {**old_request, "host": "archlinux"}}, object(), object(), DESCRIPTOR)), \
             patch.object(impl.abort, "_receipt", return_value=True), \
             patch.object(impl.abort, "_guest", return_value="empty"), \
             patch.object(impl, "_remote_marker_clean", return_value=True), \
             patch.object(impl, "_cleanup", return_value={"cleanupReceiptSha256": "cleanup"}), \
             patch.object(status.lease, "_closed", return_value=old), \
             patch.object(status.base, "_campaign_identity", side_effect=campaign_identity), \
             patch.object(status, "_remote_closed_proof", return_value=True), \
             patch.object(status.rebase.public, "_admit_pair", return_value={**PAIR, "sourceFingerprint": "current-fingerprint"}):
            bound = status._current_download_abort_successor_binding(root, new_record, DESCRIPTOR, object(), object())
        self.assertIsNotNone(bound)
        self.assertEqual("2.1.19", bound[1]["baseVersion"])

    def test_current_download_abort_successor_rejects_receipt_with_wrong_artifact_fingerprint(self):
        """A matching lease alone cannot promote a successor with different staged bytes."""
        from agent_tools import windows_cp117_download_abort_current_successor as successor

        temporary, root = self._root()
        new_lease = "e59a7483-4e38-4e7b-b8fa-0d8b2356916a"
        new_record = {**RECORD, "identity": {**IDENTITY, "leaseId": new_lease, "sourceSha": successor._SOURCE},
                      "state": "active", "role": None, "correlationId": None}
        request = {"host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": new_lease,
                   "sourceSha": successor._SOURCE,
                   "fixtureReceiptArtifactId": IDENTITY["fixtureReceiptArtifactId"],
                   "baseMsiArtifactId": IDENTITY["baseMsiArtifactId"],
                   "targetMsiArtifactId": IDENTITY["targetMsiArtifactId"]}
        old_request = {"correlationId": successor._CORRELATION, "sourceSha": successor._SOURCE,
                       **{key: request[key] for key in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId")}}
        impl = successor._impl
        with temporary, \
             patch.object(impl, "_journal", return_value=root), \
             patch.object(impl, "_read", return_value={"request": request, "abortReceipt": {"sourceFingerprint": "wrong"}}), \
             patch.object(impl, "_receipt_binding", return_value=(object(), object(), DESCRIPTOR, old_request, "retired", 42, {"bundleSha256": "bundle"})), \
             patch.object(impl.abort, "_retired_binding", return_value=(root, {"request": {**old_request, "host": "archlinux"}}, object(), object(), DESCRIPTOR)), \
             patch.object(impl.abort, "_receipt", return_value=True), \
             patch.object(impl.abort, "_guest", return_value="empty"), \
             patch.object(impl, "_remote_marker_clean", return_value=True), \
             patch.object(impl, "_cleanup", return_value={"cleanupReceiptSha256": "cleanup"}), \
             patch.object(status.lease, "_closed", return_value={**RECORD, "state": "closed", "role": None, "correlationId": None,
                 "identity": {**IDENTITY, "leaseId": successor._OLD, "sourceSha": successor._SOURCE}, "lastOutcome": "failed-cleaned", "lastEvidenceSha256": "cleanup", "server": "stopped", "credentials": "absent"}), \
             patch.object(status.base, "_campaign_identity", side_effect=lambda value, _: {**IDENTITY, "leaseId": value["correlationId"], "sourceSha": successor._SOURCE}), \
             patch.object(status, "_remote_closed_proof", return_value=True), \
             patch.object(status.rebase.public, "_admit_pair", return_value={**PAIR, "sourceFingerprint": "expected"}):
            self.assertIsNone(status._current_download_abort_successor_binding(root, new_record, DESCRIPTOR, object(), object()))

    def test_diagnostic_classifies_stale_rebase_history_contract_without_ids(self):
        """Regression: a changed history tuple must explain, not hide, a successor status failure."""
        temporary, root = self._root()
        new_record = {**RECORD, "identity": {**IDENTITY, "leaseId": NEW_LEASE}, "state": "active",
                      "role": None, "correlationId": None}
        with temporary, \
             patch.object(status.lease, "_active", return_value=new_record), \
             patch.object(status.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
             patch.object(status, "_base_binding", return_value=None), \
             patch.object(status, "_rebase_diagnostic_binding", return_value="old-history"):
            observed = status.diagnose(root, {"host": "archlinux"})
        self.assertEqual({"state": "unknown", "phase": "old-history"},
                         {key: observed[key] for key in ("state", "phase")})
        self.assertNotIn(NEW_LEASE, str(observed))

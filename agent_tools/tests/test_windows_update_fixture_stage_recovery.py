"""Causal recovery checks for the CP117 pre-dispatch fixture-stage loss."""
from __future__ import annotations

import hashlib
import io
import json
import base64
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

from agent_tools import windows_update_fixture_stage_recovery as recovery


SOURCE = "1" * 40
LEASE = "c32cb108-4d48-407e-9153-40774559ba50"
SID = "S-1-5-21-1-2-3-1002"
REQUEST = {"host": "archlinux", "correlationId": recovery._CORRELATION, "sourceSha": SOURCE,
           "fixtureReceiptArtifactId": "sha256-" + "2" * 64,
           "baseMsiArtifactId": "sha256-" + "3" * 64,
           "targetMsiArtifactId": "sha256-" + "4" * 64}
DESCRIPTOR = ("windows-cp117", "/qga", 589342, 520739, SID)
IDLE = {"state": "ready", "ready": True, "code": "READY", "installedVersion": "2.1.19",
        "productCount": 1, "activeCount": 0, "activeProcesses": []}


class StageRecoveryTest(unittest.TestCase):
    def _intent(self):
        return {"request": REQUEST, "environment": DESCRIPTOR[0], "socketPath": DESCRIPTOR[1],
                "pid": DESCRIPTOR[2], "startTicks": DESCRIPTOR[3], "expectedSid": SID,
                "sourceFingerprint": "a" * 64, "bundleSha256": "b" * 64, "bundleSize": 1,
                "fileHashes": {}, "leaseId": LEASE}

    def _patch_bound(self):
        return (patch.object(recovery, "_bound", return_value=(self._intent(),
                     {"sourceFingerprint": "a" * 64, "baseVersion": "2.1.19"}, object(), object(), DESCRIPTOR)),)

    def test_recovery_refuses_before_remote_cleanup_when_create_task_is_live(self):
        """Regression: binding-only is insufficient while QGA's create task can still win the race."""
        exact = {"state": "unknown", "correlationId": recovery._CORRELATION, "binding": "exact",
                 "phase": "guest-stage-absent", "replayAllowed": False, "nativeActionAllowed": False}
        with tempfile.TemporaryDirectory() as temporary, self._patch_bound()[0], \
             patch.object(recovery.stage, "diagnose", return_value=exact), \
             patch.object(recovery, "_remote_cleanup", return_value=False) as cleanup, \
             patch.object(recovery, "_remote_absence_reconciled", return_value=False), \
             patch.object(recovery, "_idle", return_value=True), \
             patch.object(recovery, "_campaign_closed") as close:
            result = recovery.recover(temporary, {"host": "archlinux"})
        self.assertEqual("unknown", result["state"])
        cleanup.assert_called_once()
        close.assert_not_called()

    def test_recovery_requires_two_exact_pre_cleanup_observations(self):
        good = {"state": "unknown", "correlationId": recovery._CORRELATION, "binding": "exact",
                "phase": "guest-stage-absent", "replayAllowed": False, "nativeActionAllowed": False}
        bad = {**good, "phase": "guest-stage-partial"}
        with tempfile.TemporaryDirectory() as temporary, self._patch_bound()[0], \
             patch.object(recovery.stage, "diagnose", side_effect=[good, bad]), \
             patch.object(recovery, "_remote_cleanup") as cleanup:
            result = recovery.recover(temporary, {"host": "archlinux"})
        self.assertEqual("unknown", result["state"])
        cleanup.assert_not_called()

    def test_remote_program_checks_create_task_twice_before_removing_binding(self):
        self.assertGreaterEqual(recovery._REMOTE_RECOVER.count("guest_observation()"), 2)
        self.assertIn("'createTask':'absent'", recovery._REMOTE_RECOVER)
        self.assertIn("submission-uncertain", recovery._REMOTE_RECOVER)
        self.assertLess(recovery._REMOTE_RECOVER.index("host=submitter()"),
                        recovery._REMOTE_RECOVER.index("first=guest_observation()"))

    def test_remote_reconcile_removes_only_exact_empty_job_after_absence_proofs(self):
        """Regression: an interrupt after unlink before rmdir must not strand the fixed campaign."""
        body = recovery._REMOTE_RECOVER[recovery._REMOTE_RECOVER.index("import fcntl,time"):]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); parent = root / "windows-cp117"; group = parent / "windows-update-fixture-stage"
            job = group / recovery._CORRELATION
            job.mkdir(parents=True, mode=0o700)
            for path in (root, parent, group, job):
                os.chmod(path, 0o700)
            lock = group / ".environment.lock"; lock.touch(mode=0o600); os.chmod(lock, 0o600)
            output = io.StringIO(); encoded = base64.b64encode(b"{\"version\":1,\"createTask\":\"absent\",\"guestStage\":\"absent\"}").decode()
            args = [str(root), "windows-cp117", LEASE, recovery._CORRELATION, "/qga", "589342", "520739", SID,
                    SOURCE, "a" * 64, "b" * 64, "1", REQUEST["fixtureReceiptArtifactId"],
                    REQUEST["baseMsiArtifactId"], REQUEST["targetMsiArtifactId"], "Y3JlYXRl", "reconcile"]
            calls = []
            def call(_socket, command, _arguments):
                calls.append(command)
                return {"pid": 99} if command == "guest-exec" else {
                    "exited": True, "exitcode": 0, "out-truncated": False, "err-truncated": False,
                    "out-data": encoded}
            class ProcessSafeOs:
                def __getattr__(self, name):
                    return getattr(os, name)
                @staticmethod
                def listdir(path):
                    return [] if path == "/proc" else os.listdir(path)
            namespace = {"os": ProcessSafeOs(), "stat": stat, "json": json, "base64": base64, "hashlib": hashlib,
                         "fcntl": __import__("fcntl"), "time": type("Clock", (), {"sleep": staticmethod(lambda _: None)})(),
                         "sys": type("Args", (), {"argv": ["remote", *args]})(), "live": lambda *_: True,
                         "call": call, "decode": lambda raw: raw.decode("utf-8"),
                         "require_campaign_role": lambda *_: None}
            with redirect_stdout(output):
                exec(compile(body, "recovery-empty-job", "exec"), namespace)
            self.assertFalse(job.exists(), output.getvalue())
            self.assertEqual(["guest-exec", "guest-exec-status", "guest-exec", "guest-exec-status"], calls)
            self.assertEqual({"state": "remote-absent-reconciled", "correlationId": recovery._CORRELATION,
                              "hostSubmitter": "absent", "createTask": "absent", "guestStage": "absent"},
                             json.loads(output.getvalue()))

    def test_submitter_fails_closed_when_a_live_proc_cmdline_is_unreadable(self):
        body = recovery._REMOTE_RECOVER
        start = body.index("def submitter():")
        end = body.index("def guest_observation():")
        namespace = {"os": type("Proc", (), {"listdir": staticmethod(lambda _: ["456"]),
                                                "getpid": staticmethod(lambda: 123)})(),
                     "corr": recovery._CORRELATION}
        with patch("builtins.open", side_effect=PermissionError("denied")):
            exec(body[start:end], namespace)
            observed = namespace["submitter"]()
        self.assertEqual("unknown", observed)
        self.assertLess(recovery._REMOTE_RECOVER.index("second=guest_observation()"),
                        recovery._REMOTE_RECOVER.index("os.unlink(os.path.join(job,'binding.json'))"))

    def test_recovery_closes_campaign_and_removes_only_hash_matched_bundle(self):
        good = {"state": "unknown", "correlationId": recovery._CORRELATION, "binding": "exact",
                "phase": "guest-stage-absent", "replayAllowed": False, "nativeActionAllowed": False}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intent = self._intent(); payload = b"x"; intent["bundleSize"] = len(payload)
            intent["bundleSha256"] = hashlib.sha256(payload).hexdigest()
            group = root / ".rag_index/windows-update-fixture-stage"; group.mkdir(parents=True, mode=0o700)
            bundle = group / (recovery._CORRELATION + ".zip"); bundle.write_bytes(payload); os.chmod(bundle, 0o600)
            with patch.object(recovery, "_bound", return_value=(intent, {"sourceFingerprint": "a" * 64,
                                                                            "baseVersion": "2.1.19"}, object(), object(), DESCRIPTOR)), \
                 patch.object(recovery.stage, "diagnose", return_value=good), \
                 patch.object(recovery, "_remote_cleanup", return_value=True), \
                 patch.object(recovery, "_idle", return_value=True), \
                 patch.object(recovery, "_campaign_closed", return_value=True):
                result = recovery.recover(root, {"host": "archlinux"})
            self.assertEqual("recovered", result["state"])
            self.assertFalse(bundle.exists())
            receipt = recovery._read_receipt(root)
            self.assertEqual("recovered", receipt["state"])

    def test_recovery_never_closes_campaign_without_fresh_idle_msi_observation(self):
        good = {"state": "unknown", "correlationId": recovery._CORRELATION, "binding": "exact",
                "phase": "guest-stage-absent", "replayAllowed": False, "nativeActionAllowed": False}
        with tempfile.TemporaryDirectory() as temporary, self._patch_bound()[0], \
             patch.object(recovery.stage, "diagnose", return_value=good), \
             patch.object(recovery, "_remote_cleanup", return_value=True), \
             patch.object(recovery, "_idle", return_value=False), \
             patch.object(recovery, "_campaign_closed") as close:
            result = recovery.recover(temporary, {"host": "archlinux"})
        self.assertEqual("unknown", result["state"])
        close.assert_not_called()

    def test_remote_cleaned_receipt_resumes_after_campaign_close_before_bundle_cleanup(self):
        """Regression: a closed campaign is retried from its receipt, never via stage diagnosis."""
        intent = self._intent()
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(recovery, "_bound", return_value=(intent, {"baseVersion": "2.1.19"}, object(), object(), DESCRIPTOR)), \
             patch.object(recovery, "_idle", return_value=True), \
             patch.object(recovery, "_remote_cleanup", return_value=True), \
             patch.object(recovery, "_campaign_closed", return_value=True), \
             patch.object(recovery, "_remove_bundle", side_effect=[False, True]), \
             patch.object(recovery.stage, "diagnose", side_effect=AssertionError("no diagnostic after durable cleanup")):
            root = Path(temporary)
            evidence, cleanup = recovery._evidence(intent, DESCRIPTOR)
            recovery._write_receipt(root, {"version": 1, "correlationId": recovery._CORRELATION,
                                           "leaseId": LEASE, "guestGeneration": {"socketPath": "/qga", "qemuPid": 589342,
                                                                                       "startTicks": 520739}, "evidenceSha256": evidence,
                                           "cleanupReceiptSha256": cleanup, "state": "remote-cleaned"})
            first = recovery.recover(root, {"host": "archlinux"})
            second = recovery.recover(root, {"host": "archlinux"})
        self.assertEqual("unknown", first["state"])
        self.assertEqual("recovered", second["state"])

    def test_lost_remote_unlink_response_reconciles_only_after_remote_absence_proof(self):
        exact = {"state": "unknown", "correlationId": recovery._CORRELATION, "binding": "exact",
                 "phase": "guest-stage-absent", "replayAllowed": False, "nativeActionAllowed": False}
        intent = self._intent()
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(recovery, "_bound", return_value=(intent, {"baseVersion": "2.1.19"}, object(), object(), DESCRIPTOR)), \
             patch.object(recovery.stage, "diagnose", side_effect=[exact, exact]), \
             patch.object(recovery, "_remote_cleanup", return_value=False), \
             patch.object(recovery, "_remote_absence_reconciled", return_value=True) as reconciled, \
             patch.object(recovery, "_idle", return_value=True), \
             patch.object(recovery, "_campaign_closed", return_value=True), \
             patch.object(recovery, "_remove_bundle", return_value=True):
            result = recovery.recover(temporary, {"host": "archlinux"})
        self.assertEqual("recovered", result["state"])
        reconciled.assert_called_once()

    def test_empty_job_diagnostic_reaches_guarded_reconcile(self):
        """Regression: stage diagnostic calls an empty job a binding mismatch after unlink."""
        empty = {"state": "unknown", "correlationId": recovery._CORRELATION, "binding": "mismatch",
                 "phase": "remote-binding-mismatch", "replayAllowed": False, "nativeActionAllowed": False}
        intent = self._intent()
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(recovery, "_bound", return_value=(intent, {"baseVersion": "2.1.19"}, object(), object(), DESCRIPTOR)), \
             patch.object(recovery.stage, "diagnose", side_effect=[empty, empty]), \
             patch.object(recovery, "_remote_cleanup") as cleanup, \
             patch.object(recovery, "_remote_absence_reconciled", return_value=True) as reconciled, \
             patch.object(recovery, "_idle", return_value=True), \
             patch.object(recovery, "_campaign_closed", return_value=True), \
             patch.object(recovery, "_remove_bundle", return_value=True):
            result = recovery.recover(temporary, {"host": "archlinux"})
        self.assertEqual("recovered", result["state"])
        cleanup.assert_not_called()
        reconciled.assert_called_once()

    def test_read_only_diagnose_classifies_missing_intent_before_native_observation(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(recovery.stage, "_read_intent", return_value=None), \
             patch.object(recovery, "_remote_observation") as remote:
            result = recovery.diagnose(temporary, {"host": "archlinux"})
        self.assertEqual({"state": "diagnosed", "correlationId": recovery._CORRELATION,
                          "phase": "local-intent", "recoveryAllowed": False,
                          "nativeActionAllowed": False}, result)
        remote.assert_not_called()

    def test_read_only_diagnose_reports_host_submitter_before_idle_or_closure(self):
        intent = self._intent()
        host_live = {"state": "observed", "correlationId": recovery._CORRELATION,
                     "stage": "binding-only", "hostSubmitter": "active",
                     "createTask": "absent", "guestStage": "absent"}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(recovery.stage, "_read_intent", return_value=intent), \
             patch.object(recovery.stage, "_request", side_effect=lambda value: dict(value)), \
             patch.object(recovery.public, "_admit_pair", return_value={"sourceFingerprint": "a" * 64,
                                                                           "baseVersion": "2.1.19"}), \
             patch.object(recovery.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
             patch.object(recovery, "_read_receipt", return_value=None), \
             patch.object(recovery, "_campaign_detail", return_value="active-role"), \
             patch.object(recovery, "_bound"), \
             patch.object(recovery, "_remote_observation", return_value=host_live), \
             patch.object(recovery, "_idle") as idle:
            result = recovery.diagnose(temporary, {"host": "archlinux"})
        self.assertEqual({"state": "diagnosed", "correlationId": recovery._CORRELATION,
                          "phase": "host-submitter", "recoveryAllowed": False,
                          "nativeActionAllowed": False}, result)
        idle.assert_not_called()

    def test_campaign_detail_exposes_remote_confirm_without_raw_campaign_record(self):
        intent = self._intent()
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(recovery, "_campaign_detail", return_value="remote-confirm"):
            # The public projection is intentionally only the bounded detail.
            with patch.object(recovery.stage, "_read_intent", return_value=intent), \
                 patch.object(recovery.stage, "_request", side_effect=lambda value: dict(value)), \
                 patch.object(recovery.public, "_admit_pair", return_value={"sourceFingerprint": "a" * 64,
                                                                               "baseVersion": "2.1.19"}), \
                 patch.object(recovery.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
                 patch.object(recovery, "_read_receipt", return_value=None):
                result = recovery.diagnose(temporary, {"host": "archlinux"})
        self.assertEqual({"state": "diagnosed", "correlationId": recovery._CORRELATION,
                          "phase": "campaign", "campaignDetail": "remote-confirm",
                          "recoveryAllowed": False, "nativeActionAllowed": False}, result)

    def test_bound_accepts_the_base_role_evidence_preserved_by_stage_claim(self):
        intent = self._intent()
        active = {"identity": {"leaseId": LEASE}, "state": "role-active", "role": "stage",
                  "correlationId": recovery._CORRELATION, "server": "stopped", "credentials": "absent",
                  "lastEvidenceSha256": "d" * 64, "lastOutcome": "succeeded"}
        with tempfile.TemporaryDirectory() as temporary:
            lock = os.open(Path(temporary) / "lock", os.O_RDWR | os.O_CREAT, 0o600)
            with patch.object(recovery.stage, "_read_intent", return_value=intent), \
                 patch.object(recovery.stage, "_request", side_effect=lambda value: dict(value)), \
                 patch.object(recovery.public, "_admit_pair", return_value={"sourceFingerprint": "a" * 64,
                                                                               "baseVersion": "2.1.19"}), \
                 patch.object(recovery.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
                 patch.object(recovery.base, "_campaign_identity", return_value={"leaseId": LEASE}), \
                 patch.object(recovery, "_predecessor_evidence", return_value="d" * 64), \
                 patch.object(recovery.lease, "_locked", return_value=(Path(temporary), lock)), \
                 patch.object(recovery.lease, "_active", return_value=active):
                bound = recovery._bound(Path(temporary), None)
            self.assertEqual(intent, bound[0])

    def test_bound_rejects_unverified_predecessor_evidence(self):
        intent = self._intent()
        for outcome, evidence in (("failed-cleaned", "d" * 64), ("succeeded", None), ("succeeded", "e" * 64)):
            with self.subTest(outcome=outcome, evidence=evidence), tempfile.TemporaryDirectory() as temporary:
                active = {"identity": {"leaseId": LEASE}, "state": "role-active", "role": "stage",
                          "correlationId": recovery._CORRELATION, "server": "stopped", "credentials": "absent",
                          "lastEvidenceSha256": evidence, "lastOutcome": outcome}
                lock = os.open(Path(temporary) / "lock", os.O_RDWR | os.O_CREAT, 0o600)
                with patch.object(recovery.stage, "_read_intent", return_value=intent), \
                     patch.object(recovery.stage, "_request", side_effect=lambda value: dict(value)), \
                     patch.object(recovery.public, "_admit_pair", return_value={"sourceFingerprint": "a" * 64,
                                                                                   "baseVersion": "2.1.19"}), \
                     patch.object(recovery.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
                     patch.object(recovery.base, "_campaign_identity", return_value={"leaseId": LEASE}), \
                     patch.object(recovery, "_predecessor_evidence", return_value="d" * 64), \
                     patch.object(recovery.lease, "_locked", return_value=(Path(temporary), lock)), \
                     patch.object(recovery.lease, "_active", return_value=active):
                    with self.assertRaises(recovery.WindowsUpdateFixtureStageRecoveryError):
                        recovery._bound(Path(temporary), None)

    def test_remote_cleaned_resume_accepts_exact_post_finish_and_partial_close_states(self):
        intent = self._intent()
        evidence, cleanup = recovery._evidence(intent, DESCRIPTOR)
        post_finish = {"state": "active", "role": None, "correlationId": None, "server": "stopped",
                       "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": evidence}
        partial_close = {"state": "closed", "role": None, "correlationId": None, "server": "stopped",
                         "credentials": "absent", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": cleanup}
        self.assertEqual("post-finish", recovery._campaign_resume_detail(Path.cwd(), intent, DESCRIPTOR,
                                                                            post_finish, None, "remote-cleaned"))
        self.assertEqual("closed", recovery._campaign_resume_detail(Path.cwd(), intent, DESCRIPTOR,
                                                                        None, partial_close, "remote-cleaned"))

    def test_actual_remote_cleaned_post_finish_diagnosis_skips_role_guarded_remote_probe(self):
        """Regression for CP117: stage role is gone after finish, but close may still be pending."""
        intent = self._intent(); evidence, cleanup = recovery._evidence(intent, DESCRIPTOR)
        receipt = {"version": 1, "correlationId": recovery._CORRELATION, "leaseId": LEASE,
                   "guestGeneration": {"socketPath": DESCRIPTOR[1], "qemuPid": DESCRIPTOR[2],
                                       "startTicks": DESCRIPTOR[3]}, "evidenceSha256": evidence,
                   "cleanupReceiptSha256": cleanup, "state": "remote-cleaned"}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(recovery.stage, "_read_intent", return_value=intent), \
             patch.object(recovery.stage, "_request", side_effect=lambda value: dict(value)), \
             patch.object(recovery.public, "_admit_pair", return_value={"sourceFingerprint": "a" * 64,
                                                                           "baseVersion": "2.1.19"}), \
             patch.object(recovery.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
             patch.object(recovery, "_read_receipt", return_value=receipt), \
             patch.object(recovery, "_campaign_detail", return_value="post-finish"), \
             patch.object(recovery, "_bound"), \
             patch.object(recovery, "_idle", return_value=True), \
             patch.object(recovery, "_remote_observation") as remote:
            result = recovery.diagnose(temporary, {"host": "archlinux"})
        self.assertEqual({"state": "diagnosed", "correlationId": recovery._CORRELATION,
                          "phase": "closure", "recoveryAllowed": True,
                          "nativeActionAllowed": False}, result)
        remote.assert_not_called()

    def test_read_only_remote_diagnosis_never_unlinks_or_removes_job(self):
        diagnose = recovery._REMOTE_RECOVER.index("if action=='diagnose':out")
        self.assertGreater(diagnose, recovery._REMOTE_RECOVER.index("if action=='cleanup':\n   os.unlink"))
        self.assertIn("action=='diagnose'", recovery._REMOTE_RECOVER)

    def test_recovered_receipt_never_authorizes_another_correlation(self):
        self.assertEqual(recovery._CORRELATION, "7f278204-a8da-419b-baf5-d98fb94a1526")
        with self.assertRaises(recovery.WindowsUpdateFixtureStageRecoveryError):
            recovery._request({"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})


if __name__ == "__main__":
    unittest.main()

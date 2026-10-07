"""Causal regressions for CP117 continuation after the closed 7f27 stage."""
from __future__ import annotations

import tempfile
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_cp117_campaign_rebase as rebase


OLD = "c32cb108-4d48-407e-9153-40774559ba50"
NEW = "d42cb108-4d48-407e-9153-40774559ba50"
SOURCE = "1" * 40
REQUEST = {"host": "archlinux", "leaseId": NEW, "previousLeaseId": OLD, "sourceSha": SOURCE,
           "fixtureReceiptArtifactId": "sha256-" + "2" * 64,
           "baseMsiArtifactId": "sha256-" + "3" * 64,
           "targetMsiArtifactId": "sha256-" + "4" * 64}
DESC = ("windows-cp117", "/qga", 589342, 520739, "S-1-5-21-1-2-3-1002")
IDLE = {"state": "ready", "ready": True, "code": "READY", "installedVersion": "2.1.19",
        "productCount": 1, "activeCount": 0, "activeProcesses": []}


class CampaignRebaseTests(unittest.TestCase):
    def _intent(self):
        return {"leaseId": OLD, "request": {"host": "archlinux", "correlationId": rebase.recovery._CORRELATION,
                "sourceSha": SOURCE, "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                "baseMsiArtifactId": REQUEST["baseMsiArtifactId"], "targetMsiArtifactId": REQUEST["targetMsiArtifactId"]},
                "environment": DESC[0], "socketPath": DESC[1], "pid": DESC[2], "startTicks": DESC[3], "expectedSid": DESC[4],
                "sourceFingerprint": "a" * 64}

    def _receipt(self):
        intent = self._intent()
        evidence, cleanup = rebase.recovery._evidence(intent, DESC)
        return {"version": 1, "correlationId": rebase.recovery._CORRELATION, "leaseId": OLD,
                "guestGeneration": {"socketPath": DESC[1], "qemuPid": DESC[2], "startTicks": DESC[3]},
                "evidenceSha256": evidence, "cleanupReceiptSha256": cleanup, "state": "recovered"}

    def test_request_requires_distinct_canonical_new_lease(self):
        self.assertEqual(REQUEST, rebase._request(REQUEST))
        with self.assertRaises(rebase.WindowsCp117CampaignRebaseError):
            rebase._request({**REQUEST, "leaseId": OLD})

    def test_green_creates_new_lease_only_after_closed_recovered_stage_and_idle_base(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(rebase.base, "_descriptor", return_value=(object(), object(), DESC)), \
             patch.object(rebase.recovery, "_read_receipt", return_value=self._receipt()), \
             patch.object(rebase.stage, "_read_intent", return_value=self._intent()), \
             patch.object(rebase.public, "_admit_pair", return_value={"baseVersion": "2.1.19", "sourceFingerprint": "a" * 64}), \
             patch.object(rebase.transfer, "_intent", return_value={"correlationId": OLD, "sourceSha": SOURCE, "baseMsiArtifactId": REQUEST["baseMsiArtifactId"], "environment": DESC[0], "socketPath": DESC[1], "qemuPid": DESC[2], "startTicks": DESC[3], "expectedSid": DESC[4]}), \
             patch.object(rebase.transfer, "_terminal_intent", return_value="b" * 64), \
             patch.object(rebase, "_previous_closed"), patch.object(rebase, "_idle", return_value=True), \
             patch.object(rebase.lease, "begin", return_value={"state": "active"}) as begin:
            result = rebase.start(temporary, REQUEST)
        self.assertEqual("active", result["state"])
        self.assertEqual(NEW, begin.call_args.args[1]["leaseId"])
        self.assertNotEqual(rebase.recovery._CORRELATION, NEW)

    def test_old_stage_is_never_replayed_and_second_new_lease_attempt_is_unknown(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(rebase.base, "_descriptor", return_value=(object(), object(), DESC)), \
             patch.object(rebase.recovery, "_read_receipt", return_value=self._receipt()), \
             patch.object(rebase.stage, "_read_intent", return_value=self._intent()) as stage_intent, \
             patch.object(rebase.public, "_admit_pair", return_value={"baseVersion": "2.1.19", "sourceFingerprint": "a" * 64}), \
             patch.object(rebase.transfer, "_intent", return_value={"correlationId": OLD, "sourceSha": SOURCE, "baseMsiArtifactId": REQUEST["baseMsiArtifactId"], "environment": DESC[0], "socketPath": DESC[1], "qemuPid": DESC[2], "startTicks": DESC[3], "expectedSid": DESC[4]}), \
             patch.object(rebase.transfer, "_terminal_intent", return_value="b" * 64), \
             patch.object(rebase, "_previous_closed"), patch.object(rebase, "_idle", return_value=True), \
             patch.object(rebase.lease, "begin", return_value={"state": "active"}) as begin:
            self.assertEqual("active", rebase.start(temporary, REQUEST)["state"])
            self.assertEqual("unknown", rebase.start(temporary, REQUEST)["state"])
        self.assertEqual(1, begin.call_count)
        self.assertEqual(2, stage_intent.call_count)

    def test_rejects_changed_pair_before_lease_creation(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(rebase.base, "_descriptor", return_value=(object(), object(), DESC)), \
             patch.object(rebase.recovery, "_read_receipt", return_value=self._receipt()), \
             patch.object(rebase.stage, "_read_intent", return_value=self._intent()), \
             patch.object(rebase.lease, "begin") as begin:
            result = rebase.start(temporary, {**REQUEST, "targetMsiArtifactId": "sha256-" + "9" * 64})
        self.assertEqual("unknown", result["state"])
        begin.assert_not_called()

    def test_rejects_non_idle_2_1_19_before_lease_creation(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(rebase.base, "_descriptor", return_value=(object(), object(), DESC)), \
             patch.object(rebase.recovery, "_read_receipt", return_value=self._receipt()), \
             patch.object(rebase.stage, "_read_intent", return_value=self._intent()), \
             patch.object(rebase.public, "_admit_pair", return_value={"baseVersion": "2.1.19", "sourceFingerprint": "a" * 64}), \
             patch.object(rebase.transfer, "_intent", return_value={"correlationId": OLD, "sourceSha": SOURCE, "baseMsiArtifactId": REQUEST["baseMsiArtifactId"], "environment": DESC[0], "socketPath": DESC[1], "qemuPid": DESC[2], "startTicks": DESC[3], "expectedSid": DESC[4]}), \
             patch.object(rebase.transfer, "_terminal_intent", return_value="b" * 64), \
             patch.object(rebase, "_previous_closed"), patch.object(rebase, "_idle", return_value=False), \
             patch.object(rebase.lease, "begin") as begin:
            result = rebase.start(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        begin.assert_not_called()

    def test_history_rejects_recovery_receipt_with_changed_generation_or_cleanup(self):
        intent = self._intent()
        for changed in ({"leaseId": NEW}, {"guestGeneration": {"socketPath": "/other", "qemuPid": DESC[2], "startTicks": DESC[3]}},
                        {"cleanupReceiptSha256": "f" * 64}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(rebase.recovery, "_read_receipt", return_value={**self._receipt(), **changed}), \
                 patch.object(rebase.stage, "_read_intent", return_value=intent), \
                 patch.object(rebase.public, "_admit_pair", return_value={"baseVersion": "2.1.19", "sourceFingerprint": "a" * 64}):
                with self.assertRaises(rebase.WindowsCp117CampaignRebaseError):
                    rebase._history(Path(temporary), REQUEST, DESC)

    def test_history_rejects_prior_intent_fingerprint_changed_from_artifact_pair(self):
        intent = {**self._intent(), "sourceFingerprint": "f" * 64}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(rebase.recovery, "_read_receipt", return_value=self._receipt()), \
             patch.object(rebase.stage, "_read_intent", return_value=intent), \
             patch.object(rebase.public, "_admit_pair", return_value={"baseVersion": "2.1.19", "sourceFingerprint": "a" * 64}):
            with self.assertRaises(rebase.WindowsCp117CampaignRebaseError):
                rebase._history(Path(temporary), REQUEST, DESC)

    def test_closed_campaign_requires_recovery_cleanup_hash(self):
        identity = rebase.base._campaign_identity({**REQUEST, "correlationId": OLD}, DESC)
        closed = {"identity": identity, "lastOutcome": "failed-cleaned", "lastEvidenceSha256": "f" * 64,
                  "server": "stopped", "credentials": "absent"}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(rebase.lease, "_locked", return_value=(Path(temporary), 0)), \
             patch.object(rebase.os, "close"), patch.object(rebase.lease, "_active", return_value=None), \
             patch.object(rebase.lease, "_closed", return_value=closed), patch.object(rebase.lease, "_remote_confirm", return_value=True):
            with self.assertRaises(rebase.WindowsCp117CampaignRebaseError):
                rebase._previous_closed(Path(temporary), REQUEST, DESC, object(), object(), "e" * 64)

    def test_readonly_closed_proof_is_private_exact_fresh_and_never_writes(self):
        from agent_tools import windows_cp117_historical_base_archives as history
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=root/rebase.lease._DIR
            directory.mkdir(parents=True,mode=0o700);directory.parent.chmod(0o700)
            lock=directory/'.environment.lock';lock.write_bytes(b'');lock.chmod(0o600)
            identity=rebase.base._campaign_identity({**REQUEST,'correlationId':OLD},DESC)
            closed={'version':1,'identity':identity,'sequence':7,'state':'closed','role':None,'correlationId':None,'lastOutcome':'failed-cleaned','lastEvidenceSha256':'e'*64,'server':'stopped','credentials':'absent'}
            path=directory/(OLD+'.closed.json')
            def save(value):path.write_text(json.dumps(value));path.chmod(0o600)
            save(closed);before=set(root.rglob('*'))
            with patch.object(rebase.lease,'_remote_confirm',return_value=True),patch.object(rebase.base,'_campaign_remote',return_value=object()),patch.object(rebase.lease,'_locked',side_effect=AssertionError('exclusive mutation lock')):
                with history._history_lock(root):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
                self.assertEqual(before,set(root.rglob('*')))
                for key,value in [('lastEvidenceSha256','f'*64),('lastOutcome','unknown'),('state','pending-close'),('role','base'),('credentials','cleaned'),('version',True),('sequence',False),('identity',{**identity,'expectedSid':'foreign'})]:
                    save({**closed,key:value})
                    with self.subTest(key=key),self.assertRaises(ValueError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
                save(closed)
                for raw in ('{}','invalid'):
                    active=directory/'active.json';active.write_text(raw);active.chmod(0o600)
                    with self.assertRaises(ValueError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
                    active.unlink()
                path.chmod(0o644)
                with self.assertRaises(ValueError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
                path.chmod(0o600);path.write_text('{"version":1,"version":1}')
                with self.assertRaises(ValueError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
                path.unlink();path.symlink_to(directory/'missing')
                with self.assertRaises(OSError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
                path.unlink();save(closed)
            with patch.object(rebase.lease,'_remote_confirm',return_value=False),patch.object(rebase.base,'_campaign_remote',return_value=object()):
                with self.assertRaises(ValueError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
            def changed(*args):save({**closed,'sequence':8});return True
            with patch.object(rebase.lease,'_remote_confirm',side_effect=changed),patch.object(rebase.base,'_campaign_remote',return_value=object()):
                with self.assertRaises(ValueError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)

    def test_readonly_missing_campaign_does_not_initialize_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with self.assertRaises(OSError):rebase._previous_closed_readonly(root,REQUEST,DESC,object(),object(),'e'*64)
            self.assertFalse((root/rebase.lease._DIR).exists())

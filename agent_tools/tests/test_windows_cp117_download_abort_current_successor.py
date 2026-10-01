"""Isolation and request regressions for the current download-abort successor."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_cp117_guest_abort_successor as historical
from agent_tools import windows_cp117_download_abort_current_successor as current


ARTIFACT = "sha256-" + "a" * 64
REQUEST = {"host":"archlinux", "oldLeaseId":current._OLD,
           "newLeaseId":"0f0f0f0f-1111-4222-8333-444444444444", "sourceSha":current._SOURCE,
           "fixtureReceiptArtifactId":ARTIFACT, "baseMsiArtifactId":ARTIFACT,
           "targetMsiArtifactId":ARTIFACT}


class CurrentSuccessorTests(unittest.TestCase):
    def test_exact_retired_campaign_does_not_change_historical_globals(self):
        self.assertEqual("9b4cf4c7-791a-4e51-93ac-0b8db4ac4409", current._OLD)
        self.assertNotEqual(current._OLD, historical._OLD)
        self.assertNotEqual(current._DIR, historical._DIR)
        self.assertEqual(current._DIR, current._impl._DIR)
        self.assertEqual(REQUEST, current._request(REQUEST))
        with self.assertRaises(ValueError): current._request({**REQUEST, "oldLeaseId": historical._OLD})
        with self.assertRaises(ValueError): current._request({**REQUEST, "sourceSha":"0" * 40})

    def test_status_reconcile_and_start_use_private_successor_machine(self):
        with mock.patch.object(current._impl, "status", return_value={"state":"closing"}) as status, \
             mock.patch.object(current._impl, "reconcile", return_value={"state":"opening"}) as reconcile, \
             mock.patch.object(current._impl, "start", return_value={"state":"active"}) as start:
            self.assertEqual("closing", current.status("/tmp", REQUEST)["state"])
            self.assertEqual("opening", current.reconcile("/tmp", REQUEST)["state"])
            self.assertEqual("active", current.start("/tmp", REQUEST)["state"])
        status.assert_called_once_with("/tmp", REQUEST); reconcile.assert_called_once_with("/tmp", REQUEST); start.assert_called_once_with("/tmp", REQUEST)

    def test_response_loss_reconcile_is_not_begin_replay(self):
        with mock.patch.object(current._impl, "reconcile", return_value={"state":"opening", "replayAllowed":False}) as reconcile, \
             mock.patch.object(current._impl, "start", side_effect=AssertionError("must not start")):
            self.assertEqual("opening", current.workflow("/tmp", "reconcile", REQUEST)["state"])
        reconcile.assert_called_once()

    def test_durable_intent_active_old_reports_resume_close_and_close_does_not_begin(self):
        """Use an on-disk successor receipt, then stub only remote facts."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); journal = root / current._DIR
            journal.mkdir(parents=True, mode=0o700)
            digest = current._impl._digest({})
            # A real private receipt is present before status.  The template's
            # deeper receipt validator is independently tested; this regression
            # proves the current wrapper preserves the recovery routing.
            receipt = {"version":1,"request":REQUEST,"oldLeaseId":current._OLD,
                       "abortReceipt":{},"abortReceiptSha256":"a" * 64,"cleanupReceiptSha256":"b" * 64,
                       "guestGeneration":{"socketPath":"/qga","qemuPid":17,"startTicks":29},
                       "bundleSize":42,"authorityBinding":{}}
            current._impl._write_once(journal / (REQUEST["newLeaseId"] + ".json"), receipt)
            old = {"state":"active","role":None,"correlationId":None,"server":"stopped","credentials":"absent","lastOutcome":"failed-cleaned","lastEvidenceSha256":digest,"identity":{}}
            with mock.patch.object(current._impl, "_receipt_binding", return_value=(object(),object(),("windows-cp117","/qga",17,29,"S-1-5-21-1-2-3-1002"),{"correlationId":current._CORRELATION,"sourceSha":current._SOURCE,**{k:REQUEST[k] for k in ("fixtureReceiptArtifactId","baseMsiArtifactId","targetMsiArtifactId")}},digest,42,{"bundleSha256":"d" * 64})), \
                 mock.patch.object(current._impl, "_inspect", side_effect=[{"state":"active","record":old},{"state":"unknown","record":None}]), \
                 mock.patch.object(current._impl, "_retained_empty_guest", return_value=True), \
                 mock.patch.object(current._impl, "_remote_marker_clean", return_value=True), \
                 mock.patch.object(current._impl.base, "_campaign_identity", return_value={}), \
                 mock.patch.object(current._impl.base, "_campaign_remote", return_value=object()), \
                 mock.patch.object(current._impl.lease, "_remote_confirm", return_value=True), \
                 mock.patch.object(current._impl, "_admission", return_value=(object(),object(),("windows-cp117","/qga",17,29,"S-1-5-21-1-2-3-1002"),REQUEST,{},digest,old,42,{"bundleSha256":"d" * 64})), \
                 mock.patch.object(current._impl.lease, "close", return_value={"state":"closed"}) as close, \
                 mock.patch.object(current._impl.lease, "begin", side_effect=AssertionError("must not begin")):
                self.assertEqual("resume-close", current.status(root, REQUEST)["nextAction"])
                self.assertEqual("closed", current.resume_close(root, REQUEST)["state"])
            close.assert_called_once()

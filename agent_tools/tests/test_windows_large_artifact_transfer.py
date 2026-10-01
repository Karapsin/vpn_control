import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_large_artifact_transfer as transfer
from agent_tools import windows_update_fixture_http_stage as fixture_stage

CORR = "03de8469-bcb2-49e4-a710-a3c4d1db3f64"

class TransferCoreTests(unittest.TestCase):
    def binding(self, payload):
        return {"correlationId": CORR, "sourceSha": "a" * 40, "artifactId": "sha256-" + hashlib.sha256(payload).hexdigest(), "kind": "fixture-zip", "environment": "windows-cp117", "socketPath": "/private/qga.sock", "qemuPid": 3, "startTicks": 4, "expectedSid": "S-1-5-21-1-2-3-1002"}
    def test_lost_response_is_no_replay_and_tamper_fails_read(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); data=b"large"; p=root/"x";p.write_bytes(data); b=self.binding(data)
            self.assertEqual("prepared",transfer.prepare(root,b,p)["state"])
            self.assertEqual("unknown",transfer.prepare(root,b,p)["state"])
            p.write_bytes(b"changed")
            with self.assertRaises(transfer.WindowsLargeArtifactTransferError): transfer.read(root,CORR)
    def test_receipt_requires_exact_owner_acl_and_partial_cleanup_is_denied(self):
        rec={"binding":self.binding(b"x"),"sha256":"b"*64,"length":1,"phase":"prepared"}
        self.assertEqual("unknown",transfer.project(rec,{"state":"host-staged","sha256":"b"*64,"length":1,"owner":"other","reparse":"no"},"host-staged")["state"])
        self.assertFalse(transfer.cleanup_admitted(rec,"downloaded"))
        rec["phase"]="downloaded";self.assertTrue(transfer.cleanup_admitted(rec,"downloaded"))

    def test_phase_intent_is_durable_monotonic_and_never_replays_a_download(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); data=b"fixture"; artifact=root/"fixture.zip";artifact.write_bytes(data); binding=self.binding(data)
            self.assertEqual("prepared",transfer.prepare(root,binding,artifact)["state"])
            for phase in ("host-staged","listening","guest-created","download-submitted"):
                self.assertEqual(phase,transfer.advance(root,CORR,phase)["state"])
            self.assertEqual("unknown",transfer.advance(root,CORR,"download-submitted")["state"])
            self.assertEqual("download-submitted",transfer.read(root,CORR)["phase"])

    def test_host_staged_pre_effect_close_requires_a_fsynced_local_dispatch_failure_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); data=b"fixture"; artifact=root/"fixture.zip";artifact.write_bytes(data)
            self.assertEqual("prepared",transfer.prepare(root,self.binding(data),artifact)["state"])
            self.assertEqual("host-staged",transfer.advance(root,CORR,"host-staged")["state"])
            # Remote absence alone is not proof that a delayed host operation
            # cannot still happen.  A historical unjournaled crash stays armed.
            self.assertEqual("unknown",transfer.close_host_staged_pre_effect(root,CORR)["state"])
            receipt=transfer.read(root,CORR)
            self.assertEqual("host-staged",receipt["phase"])
            self.assertNotIn("preEffectClose",receipt)

    def test_e66_failure_import_requires_exact_provenance_and_never_replays(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); artifact = root / "fixture.zip"; artifact.write_bytes(b"fixture")
            binding = {**self.binding(b"fixture"),
                       "correlationId": transfer._E66_CORRELATION,
                       "sourceSha": transfer._E66_SOURCE,
                       "artifactId": transfer._E66_ARTIFACT}
            with mock.patch.object(transfer, "_digest", return_value=7):
                self.assertEqual("prepared", transfer.prepare(root, binding, artifact)["state"])
                self.assertEqual("host-staged", transfer.advance(
                    root, transfer._E66_CORRELATION, "host-staged")["state"])
                with mock.patch.object(fixture_stage, "_e66_transcript", return_value={
                    "transcriptSha256": "a" * 64}) as transcript, mock.patch.object(
                    fixture_stage, "_e66_imported", return_value=False):
                    self.assertEqual("unknown", transfer.record_predispatch_failure(
                        root, transfer._E66_CORRELATION)["state"])
                transcript.assert_called_once()
                self.assertNotIn("dispatchFailure", transfer.read(root, transfer._E66_CORRELATION))
                with mock.patch.object(fixture_stage, "_e66_transcript", return_value={
                    "transcriptSha256": "a" * 64}), mock.patch.object(
                    fixture_stage, "_e66_imported", return_value=True):
                    self.assertEqual("failure-recorded", transfer.record_predispatch_failure(
                        root, transfer._E66_CORRELATION)["state"])
                    self.assertEqual("unknown", transfer.record_predispatch_failure(
                        root, transfer._E66_CORRELATION)["state"])
                self.assertEqual(transfer._SOURCE_OPEN_FAILURE,
                                 transfer.read(root, transfer._E66_CORRELATION)["dispatchFailure"])
                self.assertEqual("aborted", transfer.close_host_staged_pre_effect(
                    root, transfer._E66_CORRELATION)["state"])
                self.assertEqual("unknown", transfer.record_predispatch_failure(
                    root, transfer._E66_CORRELATION)["state"])
            self.assertEqual("unknown", transfer.record_predispatch_failure(root, CORR)["state"])

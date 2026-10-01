"""Status binding for the one retained-empty download-abort successor."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_cp117_campaign_status as status
from agent_tools import windows_cp117_download_abort_successor as successor


NEW = "b1387ac6-bd49-470b-9e8d-399a44760329"
REQUEST = {"host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": NEW,
           "sourceSha": successor._SOURCE, "fixtureReceiptArtifactId": "sha256-" + "a" * 64,
           "baseMsiArtifactId": "sha256-" + "b" * 64, "targetMsiArtifactId": "sha256-" + "c" * 64}
DESC = ("windows-cp117", "/qga", 12, 34, "S-1-5-21-1-2-3-1002")
OLD_REQUEST = {"correlationId": successor._CORRELATION,
               **{key: REQUEST[key] for key in ("sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId")}}
OLD_IDENTITY = status.base._campaign_identity({**OLD_REQUEST, "correlationId": successor._OLD}, DESC)
NEW_IDENTITY = status.base._campaign_identity({**OLD_REQUEST, "correlationId": NEW}, DESC)
RETIRED = "d" * 64
PAIR = {"baseVersion": "2.1.19", "sourceFingerprint": "e" * 64}
AUTHORITY = {"bundleSha256": "f" * 64}


class DownloadAbortSuccessorStatusBindingTest(unittest.TestCase):
    def _stored(self):
        return {"request": REQUEST, "abortReceipt": {"sourceFingerprint": PAIR["sourceFingerprint"]}}

    def _old(self):
        return {"identity": OLD_IDENTITY, "role": None, "correlationId": None, "server": "stopped",
                "credentials": "absent", "lastOutcome": "failed-cleaned",
                "lastEvidenceSha256": successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"]}

    def _patches(self, root, *, receipt=True, marker=True, closed=True):
        stage_record = {"request": {**OLD_REQUEST, "host": "archlinux"}}
        return (patch.object(successor, "_journal", return_value=root),
                patch.object(successor, "_read", return_value=self._stored()),
                patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, OLD_REQUEST, RETIRED, 42, AUTHORITY)),
                patch.object(successor.abort, "_retired_binding", return_value=(root, stage_record, object(), object(), DESC)),
                patch.object(successor.abort, "_receipt", return_value=receipt),
                patch.object(successor.abort, "_guest", return_value="empty"),
                patch.object(successor, "_remote_marker_clean", return_value=marker),
                patch.object(status.lease, "_closed", return_value=self._old() if closed else None),
                patch.object(status, "_remote_closed_proof", return_value=True),
                patch.object(status.rebase.public, "_admit_pair", return_value=PAIR))

    def test_exact_binding_accepts_real_six_field_stage_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); patches = self._patches(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertEqual((self._stored(), PAIR), status._download_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_missing_local_receipt_or_remote_marker_blocks_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for receipt, marker in ((False, True), (True, False)):
                patches = self._patches(root, receipt=receipt, marker=marker)
                with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                    self.assertIsNone(status._download_abort_successor_binding(
                        root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_missing_immutable_successor_receipt_blocks_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); patches = self._patches(root)
            with patches[0], patch.object(successor, "_read", return_value=None), patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertIsNone(status._download_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_missing_or_changed_closed_predecessor_blocks_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._patches(root, closed=False)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertIsNone(status._download_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))
            changed = self._old(); changed["lastEvidenceSha256"] = "0" * 64
            patches = self._patches(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(status.lease, "_closed", return_value=changed), patches[8], patches[9]:
                self.assertIsNone(status._download_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))


if __name__ == "__main__":
    unittest.main()

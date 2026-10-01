"""Campaign status accepts only the exact post guest-abort successor proof."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_cp117_campaign_status as status
from agent_tools import windows_cp117_guest_abort_successor as successor


NEW = "b1387ac6-bd49-470b-9e8d-399a44760329"
REQUEST = {
    "host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": NEW,
    "sourceSha": successor._SOURCE,
    "fixtureReceiptArtifactId": "sha256-" + "a" * 64,
    "baseMsiArtifactId": "sha256-" + "b" * 64,
    "targetMsiArtifactId": "sha256-" + "c" * 64,
}
DESC = ("windows-cp117", "/qga", 12, 34, "S-1-5-21-1-2-3-1002")
OLD_REQUEST = {
    "correlationId": successor._CORRELATION,
    **{key: REQUEST[key] for key in ("sourceSha", "fixtureReceiptArtifactId",
                                     "baseMsiArtifactId", "targetMsiArtifactId")},
}
OLD_IDENTITY = status.base._campaign_identity({**OLD_REQUEST, "correlationId": successor._OLD}, DESC)
NEW_IDENTITY = status.base._campaign_identity({**OLD_REQUEST, "correlationId": NEW}, DESC)
RETIRED = "d" * 64
PAIR = {"baseVersion": "2.1.19", "sourceFingerprint": "e" * 64}
AUTHORITY = {"bundleSha256": "f" * 64}


class GuestAbortSuccessorStatusBindingTest(unittest.TestCase):
    def _stored(self):
        return {"request": REQUEST, "abortReceipt": {"sourceFingerprint": PAIR["sourceFingerprint"]}}

    def _old(self):
        return {
            "identity": OLD_IDENTITY, "role": None, "correlationId": None,
            "server": "stopped", "credentials": "absent", "lastOutcome": "failed-cleaned",
            "lastEvidenceSha256": successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"],
        }

    def _marker_record(self):
        # This is the real stage request shape: unlike the successor's
        # campaign projection, the persisted HTTP-stage request carries host.
        return {"request": {**OLD_REQUEST, "host": "archlinux"}}

    def _binding(self, root, *, stored=None, old=None, remote=True, marker=True):
        marker_record = self._marker_record()
        marker_receipt = {"sourceFingerprint": PAIR["sourceFingerprint"]}
        return patch.object(successor, "_journal", return_value=root), \
            patch.object(successor, "_read", return_value=self._stored() if stored is None else stored), \
            patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, OLD_REQUEST, RETIRED, 42, AUTHORITY)), \
            patch.object(successor.abort, "_retired_local_binding", return_value=(root, marker_record, object(), object(), DESC)), \
            patch.object(successor.abort, "_receipt_value", return_value=(marker_receipt, RETIRED)), \
            patch.object(successor.abort, "_receipt", return_value=True), \
            patch.object(successor, "_remote_marker_clean", return_value=marker), \
            patch.object(status.lease, "_closed", return_value=self._old() if old is None else old), \
            patch.object(status.rebase.public, "_admit_pair", return_value=PAIR), \
            patch.object(status, "_remote_closed_proof", return_value=remote)

    def test_exact_guest_abort_successor_requires_every_bound_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertEqual((self._stored(), PAIR), status._guest_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_missing_or_tampered_successor_receipt_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root, stored=None)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                # The exact receipt reader returning no receipt must block status.
                with patch.object(successor, "_read", return_value=None):
                    self.assertIsNone(status._guest_abort_successor_binding(
                        root, {"identity": NEW_IDENTITY}, DESC, object(), object()))
            bad = self._stored()
            bad["abortReceipt"] = {"sourceFingerprint": "f" * 64}
            patches = self._binding(root, stored=bad)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertIsNone(status._guest_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_missing_or_tampered_old_close_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = self._binding(root, old=None)
            with missing[0], missing[1], missing[2], missing[3], missing[4], missing[5], missing[6], patch.object(status.lease, "_closed", return_value=None), missing[8], missing[9]:
                self.assertIsNone(status._guest_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))
            tampered = self._old()
            tampered["lastEvidenceSha256"] = "0" * 64
            patches = self._binding(root, old=tampered)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertIsNone(status._guest_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))
                self.assertEqual("guest-abort-old-close", status._guest_abort_successor_diagnostic_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_remote_closed_proof_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root, remote=False)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertIsNone(status._guest_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))
                self.assertEqual("guest-abort-old-close-remote", status._guest_abort_successor_diagnostic_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_changed_or_missing_remote_abort_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for marker in (False, None):
                patches = self._binding(root, marker=marker)
                with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                    self.assertIsNone(status._guest_abort_successor_binding(
                        root, {"identity": NEW_IDENTITY}, DESC, object(), object()))
                    self.assertEqual("guest-abort-marker-remote", status._guest_abort_successor_diagnostic_binding(
                        root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_pinned_successor_authority_controls_marker_readback(self):
        """Regression: a later reconstructed authority must not hide a clean marker."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root, marker=True)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], \
                 patch.object(successor.abort, "_marker", return_value="unknown"):
                self.assertEqual((self._stored(), PAIR), status._guest_abort_successor_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_diagnostic_classifies_missing_successor_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root)
            with patches[0], patch.object(successor, "_read", return_value=None), patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertEqual("guest-abort-receipt", status._guest_abort_successor_diagnostic_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_diagnostic_separates_missing_local_abort_receipt_from_remote_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root, marker=True)
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                 patch.object(successor.abort, "_receipt", return_value=False), patches[6], patches[7], patches[8], patches[9]:
                self.assertEqual("guest-abort-receipt-local", status._guest_abort_successor_diagnostic_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_diagnostic_separates_changed_marker_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root, marker=True)
            changed = {"request": {**OLD_REQUEST, "sourceSha": "0" * 40}}
            with patches[0], patches[1], patches[2], \
                 patch.object(successor.abort, "_retired_local_binding", return_value=(root, changed, object(), object(), DESC)), \
                 patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertEqual("guest-abort-marker-binding", status._guest_abort_successor_diagnostic_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))

    def test_marker_binding_rejects_successor_projection_without_stage_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = self._binding(root, marker=True)
            with patches[0], patches[1], patches[2], \
                 patch.object(successor.abort, "_retired_local_binding", return_value=(root, {"request": OLD_REQUEST}, object(), object(), DESC)), \
                 patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
                self.assertEqual("guest-abort-marker-binding", status._guest_abort_successor_diagnostic_binding(
                    root, {"identity": NEW_IDENTITY}, DESC, object(), object()))


if __name__ == "__main__":
    unittest.main()

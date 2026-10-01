"""Campaign status follows the exact post-e66 lease with old-close proof."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_cp117_campaign_status as status
from agent_tools import windows_cp117_e66_successor as successor


NEW = "68393b94-144c-405c-bc8d-bc61afa38d65"
SOURCE = "a" * 40
REQUEST = {"host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": NEW,
           "sourceSha": SOURCE, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}
DESC = ("windows-cp117", "/qga", 12, 34, "S-1-5-21-1-2-3-1002")
OLD_REQUEST = {"correlationId": successor.e66._E66_CORRELATION,
               **{key: REQUEST[key] for key in ("sourceSha", "fixtureReceiptArtifactId",
                                                 "baseMsiArtifactId", "targetMsiArtifactId")}}
OLD_IDENTITY = status.base._campaign_identity({**OLD_REQUEST, "correlationId": successor._OLD}, DESC)
NEW_IDENTITY = status.base._campaign_identity({**OLD_REQUEST, "correlationId": NEW}, DESC)
RETIRED = "e" * 64
PAIR = {"baseVersion": "2.1.19", "sourceFingerprint": "f" * 64}


class E66SuccessorStatusBindingTest(unittest.TestCase):
    def test_exact_successor_requires_remote_closed_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stored = {"request": REQUEST,
                      "retirementReceipt": {"sourceFingerprint": PAIR["sourceFingerprint"]}}
            old = {"identity": OLD_IDENTITY, "lastOutcome": "failed-cleaned",
                   "lastEvidenceSha256": successor._cleanup(DESC, RETIRED)["cleanupReceiptSha256"],
                   "credentials": "absent"}
            current = {"identity": NEW_IDENTITY}
            with patch.object(successor, "_journal", return_value=root), \
                 patch.object(successor, "_read", return_value=stored), \
                 patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, OLD_REQUEST, RETIRED)), \
                 patch.object(status.lease, "_closed", return_value=old), \
                 patch.object(status.rebase.public, "_admit_pair", return_value=PAIR), \
                 patch.object(status, "_remote_closed_proof", return_value=True):
                self.assertEqual((stored, PAIR), status._e66_successor_binding(
                    root, current, DESC, object(), object()))
            with patch.object(successor, "_journal", return_value=root), \
                 patch.object(successor, "_read", return_value=stored), \
                 patch.object(successor, "_receipt_binding", return_value=(object(), object(), DESC, OLD_REQUEST, RETIRED)), \
                 patch.object(status.lease, "_closed", return_value=old), \
                 patch.object(status.rebase.public, "_admit_pair", return_value=PAIR), \
                 patch.object(status, "_remote_closed_proof", return_value=False):
                self.assertIsNone(status._e66_successor_binding(
                    root, current, DESC, object(), object()))


if __name__ == "__main__":
    unittest.main()

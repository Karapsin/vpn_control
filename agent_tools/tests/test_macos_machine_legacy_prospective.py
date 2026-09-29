"""Causal, code-only checks for prospective CP174 unknown preservation."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import macos_machine_legacy_prospective as subject
from agent_tools.macos_machine_legacy_prospective import (
    MacLegacyProspectiveJournal, LegacyProspectiveError, ProspectiveContext,
    OLD_JOB, OLD_OPERATION, OLD_PACKAGE_SHA, OLD_REQUEST, OLD_WORKER_SHA,
)


CORRELATION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
BOOT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
CONTROLLER = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def context(**changes):
    values = dict(source_sha="a" * 40, source_fingerprint="b" * 64,
                  fixture_receipt_artifact_id="sha256-" + "c" * 64,
                  base_dmg_artifact_id="sha256-" + "d" * 64,
                  target_dmg_artifact_id="sha256-" + "e" * 64,
                  correlation_id=CORRELATION, boot_session_uuid=BOOT,
                  reservation_id="env-123456")
    values.update(changes)
    return ProspectiveContext(**values)


class Boundary:
    def __init__(self):
        self.boot = BOOT
        self.reservation = "env-123456"
        self.inputs = {
            "package.dmg": dict(device=1, inode=11, mode=0o600, size=42, sha256=OLD_PACKAGE_SHA),
            "vpn-control-install-worker": dict(device=1, inode=12, mode=0o500, size=43,
                                               sha256=OLD_WORKER_SHA),
        }
        self.protected = {"jobId": OLD_JOB, "receiptAbsent": True}
        self.public = {"ok": True, "code": "OK", "final": True,
                       "data": {"installations": [
                           {"jobId": OLD_JOB, "originControllerId": CONTROLLER,
                            "originRequestId": OLD_REQUEST, "operationId": OLD_OPERATION,
                            "phase": "unknown", "code": "OUTCOME_UNKNOWN", "final": False,
                            "cleanupCode": None, "installed": None}]}}
        self.calls = []
        self.drift_after_input = False
        self.change_between_samples = False
        self.generation_count = 0

    def generation(self):
        self.calls.append("generation")
        self.generation_count += 1
        if self.change_between_samples and self.generation_count == 3:
            self.inputs["package.dmg"]["inode"] += 1
        return self.boot, self.reservation

    def read_input(self, name):
        self.calls.append(name)
        if self.drift_after_input:
            self.boot = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        return copy.deepcopy(self.inputs[name])

    def read_protected(self):
        self.calls.append("protected")
        return copy.deepcopy(self.protected)

    def read_public(self):
        self.calls.append("public")
        return copy.deepcopy(self.public)


class Clock:
    def __init__(self):
        self.value = 1_800_000_000_000

    def __call__(self):
        self.value += 1
        return self.value


class ProspectiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.boundary = Boundary()
        self.clock = Clock()
        self.journal = MacLegacyProspectiveJournal(self.root, self.boundary, clock_ms=self.clock)

    def test_two_independent_reads_and_unchanged_after_campaign(self):
        before = self.journal.baseline(context())
        self.assertTrue(before["legacyProspectivePreserved"])
        sequence = ["generation", "package.dmg", "vpn-control-install-worker",
                    "protected", "public", "generation"]
        self.assertEqual(self.boundary.calls, sequence * 2)
        after = self.journal.verify(context())
        self.assertTrue(after["legacyProspectivePreservedAfter"])
        self.assertEqual(after["legacyProspectiveBaselineId"], before["legacyProspectiveBaselineId"])
        self.assertEqual(after["historicalOutcome"], "unknown")
        self.assertFalse(after["replayAllowed"])
        self.assertEqual(len(self.boundary.calls), 18)

    def test_pre_effect_sample_mismatch_writes_no_baseline(self):
        self.boundary.change_between_samples = True
        with self.assertRaisesRegex(LegacyProspectiveError, "samples differ"):
            self.journal.baseline(context())
        path = self.root / ".rag_index/macos-machine-legacy-prospective" / (CORRELATION + ".json")
        self.assertFalse(path.exists())

    def test_no_overwrite_and_private_durable_baseline(self):
        self.journal.baseline(context())
        path = self.root / ".rag_index/macos-machine-legacy-prospective" / (CORRELATION + ".json")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(LegacyProspectiveError, "already exists"):
            self.journal.baseline(context())

    def test_short_baseline_write_cannot_be_admitted(self):
        with patch.object(subject.os, "write", return_value=1):
            with self.assertRaisesRegex(LegacyProspectiveError, "write"):
                self.journal.baseline(context())

    def test_changed_old_input_inode_fails_after_campaign(self):
        self.journal.baseline(context())
        self.boundary.inputs["vpn-control-install-worker"]["inode"] += 1
        with self.assertRaisesRegex(LegacyProspectiveError, "changed"):
            self.journal.verify(context())

    def test_old_input_bytes_and_bool_identity_fail_closed(self):
        self.boundary.inputs["package.dmg"]["sha256"] = "f" * 64
        with self.assertRaises(LegacyProspectiveError):
            self.journal.baseline(context())
        self.boundary.inputs["package.dmg"]["sha256"] = OLD_PACKAGE_SHA
        self.boundary.inputs["package.dmg"]["device"] = True
        with self.assertRaises(LegacyProspectiveError):
            self.journal.baseline(context())

    def test_protected_receipt_or_terminal_public_outcome_fail_closed(self):
        self.boundary.protected["receiptAbsent"] = 1
        with self.assertRaises(LegacyProspectiveError):
            self.journal.baseline(context())
        self.boundary.protected["receiptAbsent"] = True
        self.boundary.public["data"]["installations"][0]["final"] = True
        with self.assertRaises(LegacyProspectiveError):
            self.journal.baseline(context())

    def test_wrong_old_operation_and_ambiguous_job_fail_closed(self):
        entry = self.boundary.public["data"]["installations"][0]
        entry["operationId"] = CORRELATION
        with self.assertRaises(LegacyProspectiveError):
            self.journal.baseline(context())
        entry["operationId"] = OLD_OPERATION
        self.boundary.public["data"]["installations"].append(copy.deepcopy(entry))
        with self.assertRaises(LegacyProspectiveError):
            self.journal.baseline(context())

    def test_generation_drift_and_context_rebinding_fail_closed(self):
        self.boundary.drift_after_input = True
        with self.assertRaisesRegex(LegacyProspectiveError, "Boot or reservation changed"):
            self.journal.baseline(context())
        self.boundary = Boundary()
        self.journal = MacLegacyProspectiveJournal(self.root, self.boundary, clock_ms=self.clock)
        self.journal.baseline(context())
        with self.assertRaisesRegex(LegacyProspectiveError, "binding changed"):
            self.journal.verify(context(source_sha="f" * 40))

    def test_tampered_journal_or_stale_read_fails_closed(self):
        self.journal.baseline(context())
        path = self.root / ".rag_index/macos-machine-legacy-prospective" / (CORRELATION + ".json")
        path.write_text("{}")
        with self.assertRaises(LegacyProspectiveError):
            self.journal.verify(context())

    def test_old_job_never_treated_as_terminal_or_replayable(self):
        self.journal.baseline(context())
        value = self.journal.verify(context())
        self.assertEqual(value["scope"], "prospective-only")
        self.assertNotIn("terminal", value)
        self.assertNotIn("historicalUnchanged", value)

    def test_terminal_five_field_binding_and_uppercase_boot(self):
        upper = context(boot_session_uuid=BOOT.upper())
        self.boundary.boot = BOOT.upper()
        before = self.journal.baseline(upper)
        after = self.journal.verify_bound(upper.source_sha, upper.correlation_id,
            upper.fixture_receipt_artifact_id, upper.boot_session_uuid,
            upper.reservation_id)
        self.assertEqual(before["legacyProspectiveBaselineId"],
                         after["legacyProspectiveBaselineId"])
        with self.assertRaisesRegex(LegacyProspectiveError, "terminal identity changed"):
            self.journal.verify_bound(upper.source_sha, upper.correlation_id,
                "sha256-" + "f" * 64, upper.boot_session_uuid, upper.reservation_id)

    def test_post_campaign_public_unknown_must_still_be_fresh(self):
        self.journal.baseline(context())
        self.boundary.public["data"]["installations"][0]["code"] = "OK"
        with self.assertRaisesRegex(LegacyProspectiveError, "no longer UNKNOWN"):
            self.journal.verify(context())


if __name__ == "__main__":
    unittest.main()

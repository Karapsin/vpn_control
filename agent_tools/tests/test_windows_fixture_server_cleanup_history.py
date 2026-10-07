"""Causal regression for local CP117 cleanup history after the abort successor."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_fixture_server_abort_successor as successor
from agent_tools import windows_update_fixture_server as server


LEASE = "e59a7483-4e38-4e7b-b8fa-0d8b2356916a"
STAGE = "11111111-1111-4111-8111-111111111111"
NEW_CLEANUP = "a1a2a3a4-1111-4222-8333-123456789abc"
GUEST = ("windows-cp117", "/fixed/cp117.qga", 713, 1241, "S-1-5-21-1-2-3-1000")


def _server_request(correlation: str) -> dict[str, str]:
    return {"host": "archlinux", "leaseId": LEASE, "stageCorrelationId": STAGE,
            "serverCorrelationId": correlation, "sourceSha": "a" * 40,
            "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
            "baseMsiArtifactId": "sha256-" + "c" * 64,
            "targetMsiArtifactId": "sha256-" + "d" * 64}


def _cleanup(mode: str, request: dict[str, str], bound: dict[str, str], *, guest=GUEST) -> dict[str, object]:
    return {"schemaVersion": 1, "mode": mode, "request": request, "serverRequest": bound,
            "environment": guest[0], "socketPath": guest[1], "qemuPid": guest[2],
            "startTicks": guest[3], "originalSid": guest[4], "serverPid": 0,
            "serverProcessStartIdentity": "", "serverPort": 0,
            "commandSha256": "e" * 64, "verifyCommandSha256": "f" * 64}


class CleanupHistoryAdmissionTest(unittest.TestCase):
    def _write_old(self, root: Path, prior: dict[str, object]) -> None:
        directory = root / server._CLEANUP_GROUP
        directory.mkdir(mode=0o700, parents=True)
        path = directory / (successor._ABORT + ".json")
        path.write_text(json.dumps(prior), encoding="utf-8")
        path.chmod(0o600)

    def test_old_same_lease_abort_blocks_then_exact_successor_allows_new_reservation(self):
        old_request = _server_request(successor._SERVER)
        prior = _cleanup("abort", {"leaseId": LEASE, "serverCorrelationId": successor._SERVER,
                                   "cleanupCorrelationId": successor._ABORT}, old_request)
        current_request = _server_request(successor._REPLACEMENT_SERVER)
        candidate = _cleanup("abort", {"leaseId": LEASE, "serverCorrelationId": successor._REPLACEMENT_SERVER,
                                        "cleanupCorrelationId": NEW_CLEANUP}, current_request)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self._write_old(root, prior)
            successor_record = {"version": 1,
                                "request": {"successorCleanupCorrelationId": successor._HISTORICAL_SUCCESSOR},
                                "serverCorrelationId": successor._SERVER,
                                "priorCleanupCorrelationId": successor._ABORT,
                                "serverRequest": old_request,
                                "guestGeneration": {"socketPath": GUEST[1], "qemuPid": GUEST[2], "startTicks": GUEST[3]}}
            successor._reserve(root, successor_record)
            successor._save_terminal(root, successor._HISTORICAL_SUCCESSOR, {"exitcode": 1})
            digest = successor._digest(successor_record["request"], GUEST, 1)
            identity = {"leaseId": LEASE, "replacement": successor._REPLACEMENT_SERVER}
            active = {"identity": identity, "state": "role-active", "role": "server-start",
                      "correlationId": successor._REPLACEMENT_SERVER, "server": "starting",
                      "credentials": "ready", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": digest}
            lock = lambda _root: (root, os.open(root, os.O_RDONLY))
            with mock.patch.object(successor.base, "_descriptor", return_value=(object(), object(), GUEST)), \
                 mock.patch.object(successor.base, "_campaign_identity", return_value=identity), \
                 mock.patch.object(successor.base, "_campaign_remote", return_value=object()), \
                 mock.patch.object(successor.lease, "_locked", side_effect=lock), \
                 mock.patch.object(successor.lease, "_active", return_value=active), \
                 mock.patch.object(successor.lease, "_remote_confirm", return_value=True), \
                 mock.patch.object(successor, "_observe", return_value={"state": "terminal", "exitcode": 1}):
                # RED: prior to this admission, the old current-lease abort is a hard block.
                with mock.patch.object(successor, "allows_cleanup_reservation", return_value=False):
                    with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "history"):
                        server._reserve_cleanup(root, candidate)
                self.assertFalse(server._cleanup_path(root, NEW_CLEANUP).exists())
                server._reserve_cleanup(root, candidate)
            self.assertEqual(candidate, server._read_cleanup_intent(root, NEW_CLEANUP))

    def test_wrong_predecessor_correlation_guest_or_active_role_refuses(self):
        old_request = _server_request(successor._SERVER)
        prior = _cleanup("abort", {"leaseId": LEASE, "serverCorrelationId": successor._SERVER,
                                   "cleanupCorrelationId": successor._ABORT}, old_request)
        candidate = _cleanup("abort", {"leaseId": LEASE, "serverCorrelationId": successor._REPLACEMENT_SERVER,
                                        "cleanupCorrelationId": NEW_CLEANUP}, _server_request(successor._REPLACEMENT_SERVER))
        for prior_correlation, observed_guest, role in (("00000000-0000-4000-8000-000000000000", GUEST, "server-start"),
                                                        (successor._ABORT, (GUEST[0], GUEST[1], 714, GUEST[3], GUEST[4]), "server-start"),
                                                        (successor._ABORT, GUEST, "server-stop")):
            with self.subTest(prior_correlation=prior_correlation, guest=observed_guest, role=role), \
                 tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                successor_record = {"version": 1,
                                    "request": {"successorCleanupCorrelationId": successor._HISTORICAL_SUCCESSOR},
                                    "serverCorrelationId": successor._SERVER,
                                    "priorCleanupCorrelationId": successor._ABORT,
                                    "serverRequest": old_request,
                                    "guestGeneration": {"socketPath": GUEST[1], "qemuPid": GUEST[2], "startTicks": GUEST[3]}}
                successor._reserve(root, successor_record)
                successor._save_terminal(root, successor._HISTORICAL_SUCCESSOR, {"exitcode": 1})
                digest = successor._digest(successor_record["request"], GUEST, 1)
                identity = {"leaseId": LEASE, "replacement": successor._REPLACEMENT_SERVER}
                active = {"identity": identity, "state": "role-active", "role": role,
                          "correlationId": successor._REPLACEMENT_SERVER, "server": "starting",
                          "credentials": "ready", "lastOutcome": "failed-cleaned", "lastEvidenceSha256": digest}
                with mock.patch.object(successor.base, "_descriptor", return_value=(object(), object(), observed_guest)), \
                     mock.patch.object(successor.base, "_campaign_identity", return_value=identity), \
                     mock.patch.object(successor.base, "_campaign_remote", return_value=object()), \
                     mock.patch.object(successor.lease, "_locked", side_effect=lambda _root: (root, os.open(root, os.O_RDONLY))), \
                     mock.patch.object(successor.lease, "_active", return_value=active), \
                     mock.patch.object(successor.lease, "_remote_confirm", return_value=True), \
                     mock.patch.object(successor, "_observe", return_value={"state": "terminal", "exitcode": 1}):
                    self.assertFalse(successor.allows_cleanup_reservation(
                        root, prior_correlation, LEASE, prior, candidate))


if __name__ == "__main__":
    unittest.main()

"""Remote CP117 same-lease server-history guard regression."""
from __future__ import annotations

import contextlib
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from agent_tools import windows_update_fixture_server as server


LEASE = "e59a7483-4e38-4e7b-b8fa-0d8b2356916a"
OLD_SERVER = "2c438d90-9a77-4acd-b4d7-ab354b85a04a"
SUCCESSOR = "bbc75e43-e220-44e8-ab60-ddc3876ba5fb"
NEW_SERVER = "316e6189-5be0-4ea0-bca1-a3905816d815"
STAGE = "11111111-1111-4111-8111-111111111111"
SOURCE = "a" * 40
RECEIPT = "sha256-" + "b" * 64
BASE = "sha256-" + "c" * 64
TARGET = "sha256-" + "d" * 64
SOCKET = "/fixed/cp117.qga"
PID = 713
TICKS = 1241
SID = "S-1-5-21-1-2-3-1000"


def _save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


class RemoteSameLeaseHistoryGuardTest(unittest.TestCase):
    def _run(self, *, terminal_exit: int) -> tuple[dict[str, object], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        parent = root / "windows-cp117"
        group = parent / "windows-update-fixture-server"
        campaign = parent / "windows-cp117-campaign"
        for directory in (parent, group, campaign):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        (group / ".environment.lock").touch(mode=0o600)
        (campaign / ".environment.lock").touch(mode=0o600)
        os.chmod(group / ".environment.lock", 0o600)
        os.chmod(campaign / ".environment.lock", 0o600)

        old = group / OLD_SERVER
        successor = old / ("successor-" + SUCCESSOR)
        old.mkdir(mode=0o700)
        successor.mkdir(mode=0o700)
        binding = {
            "leaseId": LEASE, "stageCorrelationId": STAGE, "serverCorrelationId": OLD_SERVER,
            "socketPath": SOCKET, "qemuPid": PID, "startTicks": TICKS, "originalSid": SID,
            "sourceSha": SOURCE, "sourceFingerprint": "e" * 64,
            "fixtureReceiptArtifactId": RECEIPT, "baseMsiArtifactId": BASE,
            "targetMsiArtifactId": TARGET, "commandSha256": "f" * 64, "dispatchProtocol": 2,
        }
        _save(old / "binding.json", binding)
        successor_binding = {
            "serverCorrelationId": OLD_SERVER,
            "priorCleanupCorrelationId": "710f7aaa-f92d-4fef-9f7c-57cf6e405624",
            "successorCleanupCorrelationId": SUCCESSOR, "socketPath": SOCKET,
            "qemuPid": PID, "startTicks": TICKS, "originalSid": SID,
        }
        _save(successor / "binding.json", successor_binding)
        _save(successor / "terminal.json", {"exitcode": terminal_exit})
        evidence = hashlib.sha256(json.dumps({
            "request": {"successorCleanupCorrelationId": SUCCESSOR},
            "guest": [SOCKET, PID, TICKS, SID], "exitcode": 1,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        identity = {
            "host": "archlinux", "environment": "windows-cp117", "leaseId": LEASE,
            "operator": "windows-base", "sourceSha": SOURCE,
            "fixtureReceiptArtifactId": RECEIPT, "baseMsiArtifactId": BASE,
            "targetMsiArtifactId": TARGET, "socketPath": SOCKET, "qemuPid": PID,
            "startTicks": TICKS,
        }
        _save(campaign / "active.json", {
            "version": 1, "identity": identity, "sequence": 8, "state": "role-active",
            "role": "server-start", "correlationId": NEW_SERVER, "server": "starting",
            "credentials": "ready", "lastEvidenceSha256": evidence,
            "lastOutcome": "failed-cleaned",
        })
        source = server._REMOTE_START[len(server.base._QGA):]
        prelude = """import base64,hashlib,json,os,re,stat,sys\ndef live(*_): return True\ndef call(*_): return {'pid': 99}\n"""
        original_argv = sys.argv
        sys.argv = ["qga", str(root), "windows-cp117", LEASE, NEW_SERVER, STAGE, SOCKET,
                    str(PID), str(TICKS), SID, SOURCE, "e" * 64, RECEIPT, BASE, TARGET,
                    base64.b64encode(b"powershell").decode(), hashlib.sha256(b"powershell").hexdigest()]
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exec(prelude + source, {})
        finally:
            sys.argv = original_argv
        return json.loads(output.getvalue()), root

    def test_exact_cleaned_successor_allows_one_same_lease_server_start(self):
        result, root = self._run(terminal_exit=1)
        self.assertEqual({"state": "submitted", "serverCorrelationId": NEW_SERVER}, result)
        self.assertTrue((root / "windows-cp117" / "windows-update-fixture-server" / NEW_SERVER).is_dir())

    def test_changed_successor_terminal_stays_fail_closed(self):
        result, root = self._run(terminal_exit=2)
        self.assertEqual({"state": "unknown", "serverCorrelationId": NEW_SERVER}, result)
        self.assertFalse((root / "windows-cp117" / "windows-update-fixture-server" / NEW_SERVER).exists())


if __name__ == "__main__":
    unittest.main()

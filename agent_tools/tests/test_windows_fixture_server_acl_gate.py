"""Causal source-bound ACL gate tests before the CP117 server task is claimed."""
from __future__ import annotations

import io
from types import SimpleNamespace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_server as server


LEASE = "11111111-1111-4111-8111-111111111111"
STAGE = "22222222-2222-4222-8222-222222222222"
SERVER = "33333333-3333-4333-8333-333333333333"
SOURCE = "a" * 40
REQUEST = {
    "host": "archlinux", "leaseId": LEASE, "stageCorrelationId": STAGE,
    "serverCorrelationId": SERVER, "sourceSha": SOURCE,
    "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
    "baseMsiArtifactId": "sha256-" + "c" * 64,
    "targetMsiArtifactId": "sha256-" + "d" * 64,
}
GUEST = ("/fixed/cp117.qga", 713, 1241, "S-1-5-21-1-2-3-1000")


def fixture_source(mode: str) -> bytes:
    return ("import os\n"
            "import platform\n"
            "from pathlib import Path\n\n"
            "def probe_events_path(directory):\n"
            "    events = Path(directory) / 'probe-events'\n"
            "    try:\n"
            f"        events.mkdir(mode={mode})\n"
            "    except FileExistsError:\n"
            "        pass\n"
            "    if platform.system() == 'Windows':\n"
            "        require_windows_private_acl(events, private=True, directory=True)\n"
            "    return events\n").encode()


SAFE = fixture_source("0o777 if os.name == 'nt' else 0o700")
OLD = fixture_source("0o700")


def staged(source: bytes) -> dict[str, object]:
    return {"state": "staged-not-server-ready", "sourceSha": SOURCE,
            "fileHashes": {"server/prepare_desktop_update_fixture.py":
                           hashlib.sha256(source).hexdigest()}}


def git_result(source: bytes) -> SimpleNamespace:
    return SimpleNamespace(stdout=io.BytesIO(source), wait=lambda timeout=None: 0,
                           kill=lambda: None)


class FixtureServerAclGateTest(unittest.TestCase):
    def test_old_source_is_blocked_before_reservation_role_or_task(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server.stage, "status", return_value=staged(OLD)), \
             patch.object(server.subprocess, "Popen", side_effect=lambda *args, **kwargs: git_result(OLD)), \
             patch.object(server, "_python_inventory", return_value={"path": "fixed", "sha256": "0" * 64,
                                                                        "version": "3.13.0"}), \
             patch.object(server, "_private_tls_descriptor", return_value={}), \
             patch.object(server, "_reserve") as reserve, \
             patch.object(server.lease, "claim_role") as claim, \
             patch.object(server.base, "_remote") as remote:
            self.assertEqual("blocked", server.acl_preflight(tmp, REQUEST)["state"])
            with self.assertRaisesRegex(server.WindowsUpdateFixtureServerError, "ACL preflight"):
                server.start(tmp, REQUEST)
            reserve.assert_not_called()
            claim.assert_not_called()
            remote.assert_not_called()

    def test_dead_safe_mkdir_decoy_cannot_hide_live_0700(self):
        decoy = fixture_source("0o700").replace(
            b"    if platform.system()", b"    if False:\n        events.mkdir(mode=0o777 if os.name == 'nt' else 0o700)\n    if platform.system()")
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server.stage, "status", return_value=staged(decoy)), \
             patch.object(server.subprocess, "Popen", return_value=git_result(decoy)):
            self.assertEqual("blocked", server.acl_preflight(tmp, REQUEST)["state"])

    def test_corrected_source_binds_stage_and_is_admitted_to_dispatch(self):
        descriptor = {
            "provisionId": "44444444-4444-4444-8444-444444444444",
            "paths": {
                "directory": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + STAGE,
                "certificate": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + STAGE + r"\server-cert.pem",
                "privateKey": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + STAGE + r"\server-key.pem",
                "trustStore": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + STAGE + r"\fixture-trust.p12",
            },
            "certificateSha256": "1" * 64, "privateKeySha256": "2" * 64,
            "trustStoreSha256": "3" * 64, "peerCertificateSha256": "4" * 64,
        }
        pair = {"sourceFingerprint": "5" * 64, "targetVersion": "2.2.0",
                "targetMsiSha256": "d" * 64, "targetMsiSize": 1234}
        target = SimpleNamespace(fixture_transfer_root="/private/fixture")
        python = {"path": r"C:\\Program Files\\Python313\\python.exe", "sha256": "6" * 64,
                  "version": "3.13.0"}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server.stage, "status", return_value=staged(SAFE)), \
             patch.object(server.subprocess, "Popen", side_effect=lambda *args, **kwargs: git_result(SAFE)), \
             patch.object(server, "_python_inventory", return_value=python), \
             patch.object(server, "_private_tls_descriptor", return_value=descriptor), \
             patch.object(server, "_admit_campaign", return_value=(pair, GUEST)), \
             patch.object(server.base, "_descriptor", return_value=(object(), target, ("windows-cp117", *GUEST))), \
             patch.object(server, "_reserve") as reserve, \
             patch.object(server.base, "_campaign_remote", return_value=object()), \
             patch.object(server.lease, "claim_role", return_value={"state": "role-active"}) as claim, \
             patch.object(server.base, "_remote", return_value=(b'{"state":"submitted","serverCorrelationId":"' + SERVER.encode() + b'"}')) as remote:
            self.assertEqual("ready", server.acl_preflight(tmp, REQUEST)["state"])
            self.assertEqual("submitted", server.start(tmp, REQUEST)["state"])
            reserve.assert_called_once()
            claim.assert_called_once()
            remote.assert_called_once()

    def test_mcp_acl_preflight_envelope_accepts_only_live_safe_source(self):
        with patch.object(server.stage, "status", return_value=staged(SAFE)), \
             patch.object(server.subprocess, "Popen", side_effect=lambda *args, **kwargs: git_result(SAFE)):
            accepted = mcp_server._vm_workflow_impl("windows-fixture-server-acl-preflight", REQUEST)
        self.assertTrue(accepted["ok"])
        self.assertEqual("ready", accepted["state"])
        self.assertFalse(accepted["replayAllowed"])
        self.assertFalse(accepted["nativeActionAllowed"])
        self.assertFalse(accepted["productAction"])
        with patch.object(server.stage, "status", return_value=staged(OLD)), \
             patch.object(server.subprocess, "Popen", return_value=git_result(OLD)):
            rejected = mcp_server._vm_workflow_impl("windows-fixture-server-acl-preflight", REQUEST)
        self.assertFalse(rejected["ok"])
        self.assertEqual("blocked", rejected["state"])

    def test_unavailable_source_or_stage_hash_is_unknown_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server.stage, "status", return_value={"state": "staged-not-server-ready", "sourceSha": SOURCE,
                                                                "fileHashes": {}}):
            self.assertEqual("unknown", server.acl_preflight(tmp, REQUEST)["state"])
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(server.stage, "status", return_value=staged(SAFE)), \
             patch.object(server.subprocess, "Popen", side_effect=OSError("git unavailable")):
            self.assertEqual("unknown", server.acl_preflight(tmp, REQUEST)["state"])


if __name__ == "__main__":
    unittest.main()

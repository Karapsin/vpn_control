"""Deterministic regressions for the pinned CP117 Python acquisition route."""
from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_fixture_python_acquire_transfer as transfer


LEASE = "11111111-1111-4111-8111-111111111111"
STAGE = "22222222-2222-4222-8222-222222222222"
SERVER = "33333333-3333-4333-8333-333333333333"
CORR = "44444444-4444-4444-8444-444444444444"
REQUEST = {"host": "archlinux", "leaseId": LEASE, "stageCorrelationId": STAGE,
           "serverCorrelationId": SERVER, "correlationId": CORR, "sourceSha": "a" * 40,
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}


class _Response:
    def __init__(self, payload: bytes, length: str): self.payload, self.headers = payload, {"Content-Length": length}
    def read(self, size: int) -> bytes:
        output, self.payload = self.payload[:size], self.payload[size:]
        return output
    def geturl(self): return transfer.URL
    def __enter__(self): return self
    def __exit__(self, *unused): return False


class PythonAcquireTransferTest(unittest.TestCase):
    def test_fixed_public_identity_and_private_guest_path_are_not_input(self):
        self.assertTrue(transfer.URL.startswith("https://www.python.org/ftp/python/3.13.15/"))
        self.assertEqual(29_452_944, transfer.SIZE_BYTES)
        decoded = base64.b64decode(transfer._encoded_download(CORR, "S-1-5-21-1-2-3-4")).decode("utf-16le")
        self.assertIn("mcp-python-bootstrap-", decoded)
        self.assertIn("-EncodedCommand", decoded)
        with self.assertRaises(transfer.WindowsFixturePythonAcquireTransferError):
            transfer._request({**REQUEST, "url": "https://attacker.invalid/"})

    def test_intent_precedes_download_and_duplicate_is_never_replayed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer._reserve(root, REQUEST)
            self.assertEqual(REQUEST, transfer._read(root, CORR)["request"])
            with self.assertRaises(FileExistsError):
                transfer._reserve(root, REQUEST)

    def test_start_unknown_after_durable_intent_does_not_submit_again(self):
        guest = ("/socket", 7, 8, "S-1-5-21-1-2-3-4")
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(transfer, "_admit", return_value=(object(), type("Target", (), {"fixture_transfer_root": "/private"})(), guest)), \
             mock.patch.object(transfer, "_guest_parse", return_value=True), \
             mock.patch.object(transfer.base, "_remote", return_value=None) as remote:
            self.assertEqual("unknown", transfer.start(temporary, REQUEST)["state"])
            self.assertEqual("unknown", transfer.start(temporary, REQUEST)["state"])
            self.assertEqual(1, remote.call_count)

    def test_status_never_creates_or_downloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual({"state": "intent-absent", "correlationId": CORR, "replayAllowed": False},
                             transfer.status(root, {"correlationId": CORR}))
            self.assertFalse((root / transfer._GROUP).exists())

    def test_status_requires_exact_guest_task_leaf_and_installer_proof(self):
        guest = ("/socket", 7, 8, "S-1-5-21-1-2-3-4")
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); transfer._reserve(root, REQUEST)
            command = transfer._download_command(CORR, guest[3])
            transfer._write_dispatch(root, CORR, command)
            complete = {"task": "ready", "leaf": "verified", "installer": "verified", "result": "succeeded"}
            with mock.patch.object(transfer, "_admit", return_value=(object(), target, guest)), \
                 mock.patch.object(transfer, "_guest_status", return_value=complete):
                self.assertEqual("downloaded", transfer.status(root, {"correlationId": CORR})["state"])
                for field in ("leaf", "installer"):
                    bad = dict(complete); bad[field] = "absent"
                    with mock.patch.object(transfer, "_guest_status", return_value=bad):
                        self.assertEqual("blocked", transfer.status(root, {"correlationId": CORR})["state"])

    def test_download_script_uses_windows_supported_interactive_task_and_valid_exists_guard(self):
        self.assertIn("-LogonType Interactive -RunLevel Limited", transfer._GUEST_DOWNLOAD_PS)
        self.assertIn("LogonType.ToString() -cne 'Interactive'", transfer._GUEST_STATUS_PS)
        self.assertIn("(Test-Path -LiteralPath $final) -or (Test-Path -LiteralPath $partial)",
                      base64.b64decode(transfer._download_command(CORR, "S-1-5-21-1-2-3-4")).decode("utf-16le"))

    def test_versioned_command_keeps_existing_failed_task_observable(self):
        sid = "S-1-5-21-1-2-3-4"
        old = transfer._download_command_v1(CORR, sid)
        middle = transfer._download_command_v2(CORR, sid)
        current = transfer._download_command(CORR, sid)
        self.assertNotEqual(old, middle)
        self.assertNotEqual(middle, current)
        self.assertEqual(old, transfer._command_for({"version": 1}, CORR, sid))
        self.assertEqual(middle, transfer._command_for({"version": 2}, CORR, sid))
        self.assertEqual(current, transfer._command_for({"version": 3}, CORR, sid))
        self.assertIn("download-result.json", base64.b64decode(current).decode("utf-16le"))

    def test_unknown_qga_submit_preserves_intent_without_replay(self):
        guest = ("/socket", 7, 8, "S-1-5-21-1-2-3-4")
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(transfer, "_admit", return_value=(object(), target, guest)), \
             mock.patch.object(transfer, "_guest_parse", return_value=True), \
             mock.patch.object(transfer.base, "_remote", return_value=b'{"state":"unknown"}\n'), \
             mock.patch.object(transfer, "reconcile", return_value={"state": "stopped"}) as reconcile:
            self.assertEqual("unknown", transfer.start(temporary, REQUEST)["state"])
            reconcile.assert_not_called()

    def test_reconcile_only_observes_direct_guest_task(self):
        guest = ("/socket", 7, 8, "S-1-5-21-1-2-3-4")
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); transfer._reserve(root, REQUEST)
            transfer._write_dispatch(root, CORR, transfer._download_command(CORR, guest[3]))
            with mock.patch.object(transfer, "_admit", return_value=(object(), target, guest)), \
                 mock.patch.object(transfer, "_guest_status", return_value={"task": "running", "leaf": "absent", "installer": "absent", "result": "running"}), \
                 mock.patch.object(transfer.base, "_remote") as remote:
                self.assertEqual("observed", transfer.reconcile(root, {"correlationId": CORR})["state"])
                remote.assert_not_called()

    def test_remote_programs_are_syntax_bound(self):
        compile(transfer._REMOTE_GUEST, "guest", "exec")
        compile(transfer._REMOTE_GUEST_STATUS, "guest-status", "exec")

    def test_guest_command_parse_and_account_gate_precede_durable_intent(self):
        guest = ("/socket", 7, 8, "S-1-5-21-1-2-3-4")
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(transfer, "_admit", return_value=(object(), target, guest)), \
             mock.patch.object(transfer, "_guest_parse", return_value=False), \
             mock.patch.object(transfer.base, "_remote", side_effect=AssertionError("must not submit")):
            with self.assertRaises(transfer.WindowsFixturePythonAcquireTransferError):
                transfer.start(temporary, REQUEST)
            self.assertFalse((Path(temporary) / transfer._GROUP).exists())

    def test_failure_detail_rejects_nonterminal_download_before_guest_read(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(transfer, "status", return_value={"state": "running"}), \
             mock.patch.object(transfer.base, "_remote", side_effect=AssertionError("must not read")):
            self.assertEqual("unknown", transfer.failure_detail(temporary, {"correlationId": CORR})["state"])

    def test_failure_detail_projects_only_bounded_task_and_partial_evidence(self):
        guest = ("/socket", 7, 8, "S-1-5-21-1-2-3-4")
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); transfer._reserve(root, REQUEST)
            transfer._write_dispatch(root, CORR, transfer._download_command(CORR, guest[3]))
            raw = b'{"state":"observed","value":{"version":1,"task":"exact","resultCode":1,"partial":"digest-verified","signer":"invalid","parseErrors":0,"phase":"signer"}}\n'
            with mock.patch.object(transfer, "status", return_value={"state": "failed"}), \
                 mock.patch.object(transfer, "_admit", return_value=(object(), target, guest)), \
                 mock.patch.object(transfer.base, "_remote", return_value=raw):
                result = transfer.failure_detail(root, {"correlationId": CORR})
            self.assertEqual(("observed", 1, "digest-verified", "invalid"),
                             (result["state"], result["resultCode"], result["partial"], result["signer"]))
            self.assertNotIn("path", result)


if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
"""Portable regressions for the non-replayable fixed Windows credential probe."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from native_fixture_qga import QgaObservationUnknown, QgaReadOnlyClient
import windows_credential_validity_qga as probe_module
from windows_credential_validity_qga import CredentialProbeAdmission, FixedCredentialProbeClient, MAX_CREDENTIAL_BYTES, OPERATION, TRACKED_HELPER_PATH, WindowsCredentialValidityProbe


@unittest.skipIf(os.name != "posix", "QGA private-journal operations require POSIX; import remains portable")
class FixedProbeTest(unittest.TestCase):
    correlation = "00000000-0000-0000-0000-000000000001"
    sid = "S-1-5-21-1-2-3-4"

    def admission(self, root: Path) -> CredentialProbeAdmission:
        secret = root / "credential"; secret.write_bytes(b"secret"); os.chmod(secret, 0o600)
        helper = TRACKED_HELPER_PATH
        return CredentialProbeAdmission("/qga", "fixture-vm", "fixture-user", self.sid, self.correlation, helper, hashlib.sha256(helper.read_bytes()).hexdigest(), secret)

    def probe(self, root: Path) -> WindowsCredentialValidityProbe:
        return WindowsCredentialValidityProbe(FixedCredentialProbeClient("/qga"), root / "journal")

    def test_start_has_only_fixed_command_and_private_stdin_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root)
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"pid": 7}) as exchange: result = self.probe(root).start(admission)
            request = exchange.call_args.args[1]
            self.assertEqual({"path", "arg", "input-data", "capture-output"}, set(request)); self.assertEqual("powershell.exe", request["path"])
            self.assertEqual(["-NoProfile", "-NonInteractive", "-EncodedCommand"], request["arg"][:3])
            payload = base64.b64decode(request["input-data"], validate=True)
            self.assertEqual(b"WCV1", payload[:4]); helper_size = int.from_bytes(payload[4:8], "big"); secret_size = int.from_bytes(payload[8:10], "big")
            self.assertEqual(TRACKED_HELPER_PATH.read_bytes(), payload[10:10 + helper_size]); self.assertEqual(b"secret", payload[10 + helper_size:10 + helper_size + secret_size])
            bootstrap = base64.b64decode(request["arg"][3]).decode("utf-16le")
            self.assertNotIn("secret", bootstrap); self.assertIn("Test-WindowsCredentialValidityAdmission", bootstrap); self.assertIn("approvedCallerSid='S-1-5-18'", bootstrap); self.assertIn("SHA256]::Create", bootstrap)
            self.assertEqual({"state": "submitted", "correlationId": self.correlation, "pid": 7}, result)

    def test_windows_command_is_bounded_independent_of_private_helper_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            admission = self.admission(Path(temporary))
            client = FixedCredentialProbeClient("/qga")
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"pid": 1}) as exchange:
                client._dispatch_admitted_probe(admission, b"h" * 100, b"secret")
                short_arguments = exchange.call_args.args[1]["arg"]
                client._dispatch_admitted_probe(admission, b"h" * 100_000, b"secret")
                long_arguments = exchange.call_args.args[1]["arg"]
            self.assertEqual(short_arguments, long_arguments)
            self.assertLess(probe_module._windows_command_line_length(long_arguments), 32767)
            # Helper bytes are structured stdin, never command-line content.
            with self.assertRaisesRegex(ValueError, "payload"):
                probe_module._private_payload(b"helper", b"x" * (MAX_CREDENTIAL_BYTES + 1))

    def test_private_file_admission_rejects_links_and_group_readable_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root); os.chmod(admission.credential_path, 0o640)
            with self.assertRaisesRegex(ValueError, "private credential"): self.probe(root).start(admission)
            os.chmod(admission.credential_path, 0o600); link = root / "link"; link.symlink_to(admission.credential_path)
            admission = CredentialProbeAdmission(admission.socket_path, admission.vm_identity, admission.account_name, admission.expected_sid, admission.correlation_id, admission.helper_path, admission.helper_sha256, link)
            with self.assertRaisesRegex(ValueError, "private credential"): self.probe(root).start(admission)

    def test_private_ancestor_allows_only_root_sticky_temporary_after_private_chain(self):
        uid = os.getuid()
        directories = {
            "/private-root/owned/child": types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid),
            "/private-root/owned": types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid),
            "/private-root": types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0),
            "/": types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
        }
        with patch.object(probe_module.os, "lstat", side_effect=lambda path: directories[path]):
            probe_module._private_ancestors(Path("/private-root/owned/child/credential"))
        directories["/private-root"] = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o0777, st_uid=0)
        with patch.object(probe_module.os, "lstat", side_effect=lambda path: directories[path]):
            with self.assertRaisesRegex(ValueError, "private credential"):
                probe_module._private_ancestors(Path("/private-root/owned/child/credential"))
        directories["/private-root"] = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=(uid + 1 if uid != 0 else 1))
        with patch.object(probe_module.os, "lstat", side_effect=lambda path: directories[path]):
            with self.assertRaisesRegex(ValueError, "private credential"):
                probe_module._private_ancestors(Path("/private-root/owned/child/credential"))

    def test_helper_hash_is_bound_before_guest_exec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root)
            admission = CredentialProbeAdmission(admission.socket_path, admission.vm_identity, admission.account_name, admission.expected_sid, admission.correlation_id, admission.helper_path, "0" * 64, admission.credential_path)
            with patch.object(QgaReadOnlyClient, "_exchange") as exchange:
                with self.assertRaisesRegex(ValueError, "admission"): self.probe(root).start(admission)
            exchange.assert_not_called()

    def test_missing_or_untracked_helper_fails_before_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root)
            missing = root / "missing-helper.ps1"
            admission = CredentialProbeAdmission(admission.socket_path, admission.vm_identity, admission.account_name, admission.expected_sid, admission.correlation_id, missing, admission.helper_sha256, admission.credential_path)
            with patch.object(QgaReadOnlyClient, "_exchange") as exchange:
                with self.assertRaisesRegex(ValueError, "helper|admission"):
                    self.probe(root).start(admission)
            exchange.assert_not_called()

    def test_intent_is_durable_before_one_call_and_unknown_never_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root); probe = self.probe(root)
            with patch.object(QgaReadOnlyClient, "_exchange", side_effect=QgaObservationUnknown({"execute": "guest-exec"}, "lost")) as exchange:
                self.assertEqual("unknown", probe.start(admission)["state"]); repeated = probe.start(admission)
            self.assertEqual("unknown", repeated["state"]); self.assertTrue(repeated["duplicate"]); self.assertEqual(1, exchange.call_count)
            journal = root / "journal" / (self.correlation + ".json")
            self.assertEqual("unknown", json.loads(journal.read_text())["state"]); self.assertEqual(0o600, stat.S_IMODE(journal.stat().st_mode))

    def test_status_binds_output_to_journal_pid_correlation_and_sid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root); probe = self.probe(root)
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"pid": 7}): probe.start(admission)
            receipt = {"operation": OPERATION, "correlationId": self.correlation, "expectedSid": self.sid, "success": False, "errorCategory": "invalid-credentials"}
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"exited": True, "out-data": base64.b64encode(json.dumps(receipt).encode()).decode()}) as exchange: result = probe.status(self.correlation)
            self.assertEqual(7, exchange.call_args.args[1]["pid"]); self.assertEqual("terminal", result["state"])

    def test_lost_status_reobserves_same_pid_and_persists_terminal_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root); probe = self.probe(root)
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"pid": 7}): probe.start(admission)
            with patch.object(QgaReadOnlyClient, "_exchange", side_effect=QgaObservationUnknown({"execute": "guest-exec-status"}, "lost")):
                self.assertEqual({"state": "unknown", "correlationId": self.correlation, "pid": 7}, probe.status(self.correlation))
            receipt = {"operation": OPERATION, "correlationId": self.correlation, "expectedSid": self.sid, "success": False, "errorCategory": "invalid-credentials"}
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"exited": True, "out-data": base64.b64encode(json.dumps(receipt).encode()).decode()}) as exchange:
                terminal = probe.status(self.correlation)
            self.assertEqual(7, exchange.call_args.args[1]["pid"])
            self.assertEqual({"state": "terminal", "correlationId": self.correlation, "pid": 7, "success": False, "errorCategory": "invalid-credentials"}, terminal)
            self.assertEqual(terminal, probe.status(self.correlation))
            self.assertEqual(terminal | {"duplicate": True}, probe.start(admission))

    def test_duplicate_correlation_rejects_different_immutable_binding_before_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root); probe = self.probe(root)
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"pid": 7}) as exchange:
                probe.start(admission)
                changed = CredentialProbeAdmission(admission.socket_path, admission.vm_identity, "other-user", admission.expected_sid, admission.correlation_id, admission.helper_path, admission.helper_sha256, root / "missing-credential")
                with self.assertRaisesRegex(ValueError, "binding"):
                    probe.start(changed)
            self.assertEqual(1, exchange.call_count)

    def test_bad_receipt_becomes_unknown_and_fixed_transport_rejects_other_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); admission = self.admission(root); probe = self.probe(root)
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"pid": 7}): probe.start(admission)
            bad = {"operation": OPERATION, "correlationId": "wrong", "expectedSid": self.sid, "success": True, "errorCategory": "none"}
            with patch.object(QgaReadOnlyClient, "_exchange", return_value={"exited": True, "out-data": base64.b64encode(json.dumps(bad).encode()).decode()}): self.assertEqual("unknown", probe.status(self.correlation)["state"])
            with self.assertRaises(ValueError): FixedCredentialProbeClient("/qga")._call("guest-file-write", {})


if __name__ == "__main__": unittest.main()

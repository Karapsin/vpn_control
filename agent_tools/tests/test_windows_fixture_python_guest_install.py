"""Causal, portable CP95 installer-route regressions."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_fixture_python_guest_install as install

LEASE = "11111111-1111-4111-8111-111111111111"
STAGE = "22222222-2222-4222-8222-222222222222"
SERVER = "44444444-4444-4444-8444-444444444444"
CORR = "33333333-3333-4333-8333-333333333333"
REQUEST = {"host": "archlinux", "leaseId": LEASE, "stageCorrelationId": STAGE, "serverCorrelationId": SERVER, "correlationId": CORR,
           "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64, "targetMsiArtifactId": "sha256-" + "d" * 64}


class Cp95PythonGuestInstallTest(unittest.TestCase):
    def test_fixed_per_user_installer_and_limited_token_are_not_input(self):
        self.assertEqual(29_452_944, install.SIZE_BYTES)
        self.assertIn("python-3.13.15-amd64.exe", install._paths(CORR)["installer"])
        self.assertIn("-LogonType Interactive -RunLevel Limited", install._START_PS)
        self.assertIn("LogonType.ToString() -ceq 'Interactive'", install._STATUS_PS)
        self.assertIn("InstallAllUsers=0 PrependPath=0 Include_launcher=0 Include_pip=0 Include_test=0", install._START_PS)
        self.assertIn("Get-FileHash", install._START_PS); self.assertIn("Get-AuthenticodeSignature", install._STATUS_PS)
        self.assertIn("Assert-PrivateTree", install._START_PS)
        self.assertIn("Get-ScheduledTaskInfo -TaskPath", install._STATUS_PS)
        with self.assertRaises(install.WindowsFixturePythonGuestInstallError): install._request({**REQUEST, "url": "x"})

    def test_existing_profile_ancestors_allow_windows_owner_but_leaf_requires_user_sid(self):
        self.assertIn("$index -lt 4", install._PRIVATE_TREE_PS)
        self.assertIn("$allowed -notcontains $owner", install._PRIVATE_TREE_PS)
        self.assertIn("$owner -cne $sid", install._PRIVATE_TREE_PS)

    def test_profile_read_ace_is_allowed_but_foreign_write_is_rejected(self):
        self.assertIn("FileSystemRights]::WriteData", install._PRIVATE_TREE_PS)
        self.assertIn("$rule.FileSystemRights -band $writeMask", install._PRIVATE_TREE_PS)
        self.assertNotIn("FileSystemRights]::Modify", install._PRIVATE_TREE_PS)

    def test_paths_are_exact_windows_paths_with_single_separators(self):
        paths = install._paths(CORR)
        self.assertEqual(r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + CORR,
                         paths["leaf"])
        self.assertEqual(paths["leaf"] + r"\python-3.13.15-amd64.exe", paths["installer"])
        self.assertNotIn("\\\\", paths["installer"])

    def test_local_intent_is_durable_and_duplicate_cannot_replay(self):
        record = {"request": REQUEST}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); install._reserve(root, record)
            self.assertEqual(record, install._read_intent(root, CORR))
            with self.assertRaises(FileExistsError): install._reserve(root, record)

    def test_start_crash_boundary_returns_unknown_without_second_effect(self):
        guest = ("/socket", 8, 9, "S-1-5-21-1-2-3-4")
        pair = {"sourceFingerprint": "e" * 64}
        config = object(); target = type("Target", (), {"fixture_transfer_root": "/private"})()
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(install, "_admit", return_value=(pair, guest)), \
             mock.patch.object(install.transfer, "_read", return_value={"request": REQUEST}), \
             mock.patch.object(install.transfer, "status", return_value={"state": "downloaded"}), \
             mock.patch.object(install.base, "_descriptor", return_value=(config, target, ("windows-cp117", *guest))), \
             mock.patch.object(install.base, "_remote", return_value=None):
            self.assertEqual("unknown", install.start(temp, REQUEST)["state"])
            self.assertEqual("unknown", install.start(temp, REQUEST)["state"])

    def test_install_refuses_unverified_or_mismatched_transfer_before_intent(self):
        guest = ("/socket", 8, 9, "S-1-5-21-1-2-3-4")
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(install, "_admit", return_value=({"sourceFingerprint": "e" * 64}, guest)), \
             mock.patch.object(install.transfer, "_read", return_value={"request": REQUEST}), \
             mock.patch.object(install.transfer, "status", return_value={"state": "blocked"}), \
             mock.patch.object(install.base, "_remote", side_effect=AssertionError("must not install")):
            with self.assertRaises(install.WindowsFixturePythonGuestInstallError):
                install.start(temp, REQUEST)
            self.assertFalse((Path(temp) / install._GROUP).exists())

    def test_diagnostic_requires_existing_bound_intent_before_guest_probe(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(install.base, "_remote", side_effect=AssertionError("must not probe")):
            self.assertEqual("intent-absent", install.diagnose(temp, {"correlationId": CORR})["state"])

    def test_success_needs_every_independent_readback(self):
        record = {"request": REQUEST, "socketPath": "/socket", "qemuPid": 8, "startTicks": 9, "originalSid": "S-1-5-21-1-2-3-4"}
        with tempfile.TemporaryDirectory() as temp:
            install._reserve(Path(temp), record)
            full = {"intent": "verified", "private": "verified", "task": "ready", "installer": "verified", "result": "succeeded", "registry": "verified", "python": "verified"}
            with mock.patch.object(install, "_observe", return_value=full): self.assertEqual("succeeded", install.status(temp, {"correlationId": CORR})["state"])
            for field in ("installer", "registry", "python"):
                bad = dict(full); bad[field] = "absent"
                with self.subTest(field=field), mock.patch.object(install, "_observe", return_value=bad): self.assertEqual("blocked", install.status(temp, {"correlationId": CORR})["state"])

    def test_absent_task_or_guest_intent_is_blocked_not_running(self):
        record = {"request": REQUEST, "socketPath": "/socket", "qemuPid": 8, "startTicks": 9, "originalSid": "S-1-5-21-1-2-3-4"}
        full = {"intent": "verified", "private": "verified", "task": "ready", "installer": "verified", "result": "succeeded", "registry": "verified", "python": "verified"}
        with tempfile.TemporaryDirectory() as temp:
            install._reserve(Path(temp), record)
            for field, absent in (("task", "absent"), ("intent", "absent"), ("private", "absent")):
                observed = dict(full); observed[field] = absent
                with self.subTest(field=field), mock.patch.object(install, "_observe", return_value=observed):
                    self.assertEqual("blocked", install.status(temp, {"correlationId": CORR})["state"])

    def test_observed_task_completion_maps_to_terminal_status(self):
        self.assertEqual("succeeded", install._completion("ready", 0))
        self.assertEqual("running", install._completion("running", None))
        self.assertEqual("running", install._completion("queued", 267009))
        self.assertEqual("failed", install._completion("ready", 1603))
        self.assertEqual("unknown", install._completion("ready", 267009))

    def test_status_and_collect_are_finite_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(install, "_observe", return_value=None):
            self.assertEqual({"state": "intent-absent", "correlationId": CORR, "replayAllowed": False}, install.status(temp, {"correlationId": CORR}))
            self.assertEqual({"state": "intent-absent", "correlationId": CORR, "replayAllowed": False}, install.collect(temp, {"correlationId": CORR}))


if __name__ == "__main__": unittest.main()

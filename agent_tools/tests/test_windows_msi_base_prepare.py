from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_msi_base_prepare as base


CORR = "05fd80ad-b93f-4450-a3e5-a67d14f24478"
SOURCE = "a" * 40
ARTIFACT = "sha256-" + "b" * 64
REQUEST = {"host": "archlinux", "correlationId": CORR, "sourceSha": SOURCE,
           "fixtureReceiptArtifactId": ARTIFACT, "baseMsiArtifactId": ARTIFACT,
           "targetMsiArtifactId": ARTIFACT, "expectedCurrentVersion": "2.1.17"}
PAIR = {"sourceSha": SOURCE, "sourceFingerprint": "c" * 64,
        "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
        "targetArtifactId": ARTIFACT, "baseVersion": "2.1.19", "targetVersion": "2.2.0",
        "baseCliSha256": "d" * 64, "baseAppJarSha256": "e" * 64,
        "baseHelperSha256": "f" * 64, "baseAppJarName": "desktopApp-2.1.19.jar"}


class BasePrepareTests(unittest.TestCase):
    def test_exact_request_and_canonical_correlation(self):
        self.assertEqual(base._request(REQUEST), REQUEST)
        for change in ({"host": "other"}, {"extra": 1}, {"correlationId": CORR.upper()},
                       {"baseMsiArtifactId": "b" * 64}):
            value = dict(REQUEST, **change)
            with self.assertRaises(base.WindowsMsiBasePrepareError):
                base._request(value)

    def test_original_user_task_binds_msi_and_installed_bytes(self):
        body = base._task(CORR, PAIR, "2.1.17", "S-1-5-21-1-2-3-1002")
        for token in ("SessionId", "RunLevel Limited", "msiexec.exe", "MSIINSTALLPERUSER=1",
                      "S-1-5-21-1-2-3-1002", PAIR["baseCliSha256"], PAIR["baseHelperSha256"],
                      "Get-FileHash", "DisplayVersion"):
            if token == "RunLevel Limited":
                self.assertIn("RunLevel Limited", base._bootstrap(CORR, PAIR, "2.1.17", "S-1-5-21-1-2-3-1002"))
            else:
                self.assertIn(token, body)
        self.assertIn("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", body)

    def test_product_inventory_accepts_only_one_exact_hklm_or_hkcu_registration(self):
        product = {"version": "2.1.19", "productCode": "{6C1D6870-76CD-3552-9176-F6AE1A3E268E}",
                   "installLocation": "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\", "hive": "HKCU"}
        self.assertTrue(base._unique_product([product], "2.1.19"))
        self.assertFalse(base._unique_product([product, dict(product, hive="HKLM")], "2.1.19"))
        self.assertFalse(base._unique_product([dict(product, version="2.1.17")], "2.1.19"))
        self.assertFalse(base._unique_product([dict(product, installLocation="C:\\Other")], "2.1.19"))

    def test_downgrade_is_rejected_before_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            newer = dict(REQUEST, expectedCurrentVersion="2.2.0")
            with patch.object(base.windows_msi_public_scenario, "_admit_pair", return_value=PAIR):
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError, "newer"):
                    base._admit(Path(directory), newer)

    def test_transfer_timeout_is_bounded_and_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "base.msi"
            package.write_bytes(b"source")
            with patch.object(base.windows_credential_probe_ssh, "_remote_command", return_value=("python3", "-c", "pass")), \
                 patch.object(base.ssh_transport, "build_ssh_argv", return_value=["ssh", "archlinux"]), \
                 patch.object(base.subprocess, "run", side_effect=subprocess.TimeoutExpired("ssh", 1800)) as run:
                self.assertIsNone(base._remote(object(), "", (), package, 1800))
                self.assertEqual(run.call_args.kwargs["timeout"], 1800)
                self.assertTrue(run.call_args.kwargs["stdin"].closed)

    def test_preflight_is_inert_and_bounded(self):
        script = base._powershell_preflight_script()
        self.assertIn("Parser]::ParseInput", script)
        self.assertNotIn("Start-ScheduledTask", script)
        self.assertNotIn("msiexec.exe", script)
        self.assertLess(len(__import__("base64").b64encode(script.encode("utf-16le"))), 30000)

    def test_readiness_binds_product_version_idle_owner_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            descriptor = (object(), Target(), ("windows-cp117", "/qga.sock", 589342, 520739,
                       "S-1-5-21-1-2-3-1002"))
            inventory = {"version": 1, "code": "READY", "installedVersion": "2.1.17",
                         "productCount": 1, "activeCount": 0, "activeKinds": [], "activeProcesses": [],
                         "workspaceLockPid": None, "ownedExplorerCount": 1}
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote") as remote:
                remote.return_value = json.dumps({"state": "observed", "inventory": inventory}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "ready")
                remote.return_value = json.dumps({"state": "observed", "inventory": dict(inventory, activeCount=1)}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")
                remote.return_value = json.dumps({"state": "observed", "inventory": dict(inventory, code="ACTIVE_PROCESS", activeCount=1, activeKinds=["msiexec"])}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")
                observed = dict(inventory, code="ACTIVE_PROCESS", activeCount=1,
                                activeKinds=["vpn-control-cli"], activeProcesses=[{"kind": "vpn-control-cli", "pid": 1234,
                                  "parentPid": 4, "startedAtUtc": "2026-09-28T10:00:00Z", "sessionId": 1,
                                  "originalUser": True, "role": "owner", "currentWorkspaceOwner": True}],
                                workspaceLockPid=1234)
                remote.return_value = json.dumps({"state": "observed", "inventory": observed}).encode()
                actual = base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})
                self.assertEqual(actual["activeKinds"], ["vpn-control-cli"])
                self.assertEqual(actual["activeProcesses"][0]["role"], "owner")
                remote.return_value = json.dumps({"state": "observed", "inventory": dict(observed, activeKinds=["private-process-name"])}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")
                remote.return_value = None
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")

    def test_readiness_script_only_observes_cp117_state(self):
        script = base._readiness_script("2.1.17", "S-1-5-21-1-2-3-1002")
        self.assertIn("HKEY_USERS", script)
        self.assertIn("GetOwnerSid", script)
        self.assertIn("ACTIVE_PROCESS", script)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn("Start-ScheduledTask", script)

    def test_unknown_submission_reserves_once_and_never_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "base.msi"
            package.write_bytes(b"x")
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), Target(),
                     ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_open_base_campaign", return_value=CORR), \
                 patch.object(base, "_remote", return_value=None) as remote:
                result = base.start(root, REQUEST)
                self.assertEqual(result["state"], "unknown")
                self.assertFalse(result["replayAllowed"])
                self.assertEqual(base.start(root, REQUEST)["state"], "unknown")
                self.assertEqual(remote.call_count, 1)
                self.assertEqual(base._private_intent(root, CORR)["request"], REQUEST)

    def test_legacy_reconciliation_blocks_before_base_intent_or_guest_submission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "base.msi"; package.write_bytes(b"x")
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), Target(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base.windows_msi_public_scenario, "preinstall_status", return_value={
                    "state": "observed", "jobId": base._LEGACY_JOB, "phase": "Failed",
                    "code": "RUNTIME_FAILED", "sequence": 3}), \
                 patch.object(base, "readiness", return_value={"state": "ready", "activeCount": 0}), \
                 patch.object(base, "_legacy_task_observation", return_value={"state": "blocked"}), \
                 patch.object(base, "_remote") as remote:
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError,
                                            "CP117_LEGACY_CLEANUP_UNVERIFIED"):
                    base.start(root, REQUEST)
                remote.assert_not_called()
                self.assertIsNone(base._private_intent(root, CORR))

    def test_legacy_cleanup_requires_exact_terminal_idle_task_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                          "S-1-5-21-1-2-3-1002")
            protected = {"state": "observed", "jobId": base._LEGACY_JOB,
                         "phase": "Failed", "code": "RUNTIME_FAILED", "sequence": 3}
            clean = {"state": "cleaned", "version": 1, "code": "CLEANED",
                     "legacyTaskCount": 0, "otherTaskCount": 0, "activeInstallerCount": 0}
            history = {"state": "clean", "groups": {"windows-msi-base": [],
                "windows-msi-target": [], "windows-msi-public": [base._LEGACY_CORRELATION]}}
            with patch.object(base.windows_msi_public_scenario, "preinstall_status", return_value=protected), \
                 patch.object(base, "readiness", return_value={"state": "ready", "activeCount": 0}), \
                 patch.object(base, "_legacy_task_observation", return_value=clean), \
                 patch.object(base, "_legacy_history_observation", return_value=history), \
                 patch.object(base.campaign_lease, "attest_legacy_closed") as attest:
                base._require_reconciled_legacy(root, descriptor, "2.1.17")
                proof = attest.call_args.args[1]
                self.assertEqual(proof["terminalJobId"], base._LEGACY_JOB)
                self.assertEqual(proof["correlationId"], base._LEGACY_CORRELATION)
                self.assertTrue(proof["activeInstallerProcessesAbsent"])
            body = base._legacy_task_script()
            self.assertIn("Get-ScheduledTask", body)
            self.assertIn(base._LEGACY_CORRELATION, body)
            self.assertNotIn("Unregister-ScheduledTask", body)
            self.assertNotIn("Start-ScheduledTask", body)
            self.assertNotIn("Stop-Process", body)
            self.assertNotIn("os.mkdir", base._LEGACY_HISTORY)

    def test_shared_campaign_rejects_second_route_and_mismatched_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                          "S-1-5-21-1-2-3-1002")
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            def journal(action, payload):
                desired = payload["desired"]
                return json.dumps({"version": 1, "action": action, "leaseId": CORR,
                    "recordSha256": base.campaign_lease._digest(desired),
                    "state": "confirmed"}).encode()
            with patch.object(base, "_require_reconciled_legacy"), \
                 patch.object(base, "_campaign_remote", return_value=journal):
                self.assertEqual(base._open_base_campaign(root, REQUEST, object(), Target(), descriptor), CORR)
                with self.assertRaises(base.campaign_lease.Cp117LeaseError):
                    base._open_base_campaign(root, dict(REQUEST, correlationId=
                        "70fa550a-a622-4123-b89c-f68a087ce808"), object(), Target(), descriptor)
                with self.assertRaises(base.WindowsMsiBasePrepareError):
                    base._verified_active_campaign(root, dict(REQUEST, targetMsiArtifactId=
                        "sha256-" + "f" * 64), descriptor, object(), Target(), require_server=False)

    def test_live_receipt_recheck_binds_pair_and_generation_after_claim(self):
        expected = base._campaign_identity(REQUEST, ("windows-cp117", "/qga.sock", 589342,
            520739, "S-1-5-21-1-2-3-1002"))
        receipt = {key: expected[key] for key in ("leaseId", "sourceSha",
            "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId",
            "socketPath", "qemuPid", "startTicks")}
        receipt.update(serverReady=True, liveReceiptSha256="a" * 64)
        self.assertTrue(base._live_receipt_matches(receipt, expected))
        self.assertFalse(base._live_receipt_matches(dict(receipt, startTicks=520740), expected))
        self.assertFalse(base._live_receipt_matches(dict(receipt, serverReady=False), expected))

    def test_second_correlation_is_blocked_after_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": REQUEST, "pair": PAIR})
            another = dict(REQUEST, correlationId="70fa550a-a622-4123-b89c-f68a087ce808")
            with self.assertRaises(base.WindowsMsiBasePrepareError):
                base._reserve(root, {"request": another, "pair": PAIR})

    def test_status_rejects_forged_passed_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            forged = {"state": "observed", "correlationId": CORR,
                      "result": {"version": 1, "correlationId": CORR, "stage": "READBACK",
                                 "result": "PASSED", "exitCode": 0}}
            with patch.object(base, "_descriptor", return_value=(object(), Target(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_remote", return_value=json.dumps(forged).encode()):
                self.assertEqual(base.status(root, {"correlationId": CORR})["state"], "unknown")

    def test_base_role_finish_requires_native_terminal_and_idle_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": REQUEST, "pair": PAIR, "leaseId": CORR})
            terminal = {"state": "terminal", "correlationId": CORR, "result": "PASSED",
                        "stage": "READBACK", "exitCode": 0, "sourceSha": SOURCE,
                        "baseArtifactId": ARTIFACT}
            idle = {"state": "ready", "activeCount": 0, "installedVersion": PAIR["baseVersion"]}
            with patch.object(base, "status", return_value=dict(terminal, result="FAILED")), \
                 patch.object(base, "readiness", return_value=idle), \
                 patch.object(base.campaign_lease, "finish_role") as finish:
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError, "terminal"):
                    base.finish_observed(root, CORR)
                finish.assert_not_called()
            with patch.object(base, "status", return_value=terminal), \
                 patch.object(base, "readiness", return_value=dict(idle, activeCount=1)), \
                 patch.object(base.campaign_lease, "finish_role") as finish:
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError, "cleanup"):
                    base.finish_observed(root, CORR)
                finish.assert_not_called()
            with patch.object(base, "status", return_value=terminal), \
                 patch.object(base, "readiness", return_value=idle), \
                 patch.object(base, "_descriptor", return_value=(object(), object(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_verified_claimed_campaign"), \
                 patch.object(base.campaign_lease, "finish_role", return_value={"state": "active"}) as finish:
                self.assertEqual(base.finish_observed(root, CORR)["state"], "active")
                self.assertEqual(finish.call_args.args[1:4], (CORR, "base", CORR))


if __name__ == "__main__":
    unittest.main()

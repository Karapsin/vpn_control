from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_msi_target_prepare as target


CORR = "d57d27cc-2b8f-4bea-a657-388c7429914c"
CONTROLLER = "8e9b16af-1196-4f76-984a-d83c802e7490"
SOURCE = "a" * 40
ARTIFACT = "sha256-" + "b" * 64
SID = "S-1-5-21-1-2-3-1002"
REQUEST = {"host": "archlinux", "correlationId": CORR, "sourceSha": SOURCE,
           "fixtureReceiptArtifactId": ARTIFACT, "baseMsiArtifactId": ARTIFACT,
           "targetMsiArtifactId": ARTIFACT, "controllerId": CONTROLLER,
           "ownerPid": 3640, "ownerStartedAtUtc": "2026-09-28T10:00:00Z"}
PAIR = {"sourceSha": SOURCE, "sourceFingerprint": "c" * 64,
        "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT, "targetArtifactId": ARTIFACT,
        "baseVersion": "2.1.19", "targetVersion": "2.2.0", "baseCliSha256": "d" * 64,
        "baseAppJarName": "desktopApp-2.1.19.jar", "baseAppJarSha256": "e" * 64,
        "baseHelperSha256": "f" * 64, "targetMsiSha256": "1" * 64,
        "targetMsiSize": 123456}
FIXTURE = {"trustStore": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-11111111-1111-4111-8111-111111111111\fixture-trust.p12",
           "trustStoreSha256": "e" * 64, "port": 53633, "probeReceiptSha256": "f" * 64}


class TargetPrepareTests(unittest.TestCase):
    def test_intent_write_failure_cannot_claim_target_role_or_dispatch(self):
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(target, "_require_fixture_network_admission", return_value=CORR), \
             patch.object(target, "readiness", return_value={"state": "ready"}), \
             patch.object(target, "_pair", return_value=PAIR), \
             patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
             patch.object(target, "_verified_network_context", return_value=FIXTURE), \
             patch.object(target, "_reserve", side_effect=OSError("fsync failed")), \
             patch.object(target.base.campaign_lease, "claim_role") as claim, \
             patch.object(target.base, "_remote") as remote:
            with self.assertRaisesRegex(OSError, "fsync failed"):
                target.start(directory, REQUEST)
            claim.assert_not_called()
            remote.assert_not_called()

    def test_cli_only_proxy_settings_cannot_admit_owner_jvm_network(self):
        probe = {"ownerTransportVerified": True, "ownerPid": REQUEST["ownerPid"],
                 "ownerStartedAtUtc": REQUEST["ownerStartedAtUtc"],
                 "proxyPort": FIXTURE["port"], "trustStoreSha256": FIXTURE["trustStoreSha256"]}
        self.assertFalse(target._owner_jvm_network_bound(probe, REQUEST, FIXTURE["port"],
                                                          FIXTURE["trustStoreSha256"]))
        admitted = dict(probe, ownerJvmNetworkVerified=True, ownerJvmPid=REQUEST["ownerPid"],
                        ownerJvmStartedAtUtc=REQUEST["ownerStartedAtUtc"],
                        ownerJvmProxyPort=FIXTURE["port"],
                        ownerJvmTrustStoreSha256=FIXTURE["trustStoreSha256"])
        self.assertTrue(target._owner_jvm_network_bound(admitted, REQUEST, FIXTURE["port"],
                                                         FIXTURE["trustStoreSha256"]))
        for changed in ({"ownerJvmPid": True}, {"ownerJvmProxyPort": 443},
                        {"ownerJvmTrustStoreSha256": "0" * 64},
                        {"ownerJvmStartedAtUtc": "2026-09-29T10:00:00Z"},
                        {"ownerJvmNetworkVerified": False}):
            self.assertFalse(target._owner_jvm_network_bound(dict(admitted, **changed), REQUEST,
                                                              FIXTURE["port"], FIXTURE["trustStoreSha256"]))

    def test_exact_bound_request_rejects_changed_owner_and_extra_field(self):
        self.assertEqual(target._request(REQUEST), REQUEST)
        for change in ({"ownerPid": True}, {"ownerStartedAtUtc": "now"},
                       {"controllerId": CONTROLLER.upper()}, {"extra": 1},
                       {"targetMsiArtifactId": "1" * 64}):
            with self.subTest(change=change), self.assertRaises(target.WindowsMsiTargetPrepareError):
                target._request(dict(REQUEST, **change))

    def test_task_uses_public_check_download_and_exact_cache_readback(self):
        body = target._task(CORR, REQUEST, PAIR, SID, FIXTURE)
        for token in ("RunLevel Limited", "Start-ScheduledTask"):
            self.assertIn(token, target._bootstrap(CORR, REQUEST, PAIR, SID, FIXTURE))
        for token in ("updates','check", "updates','download", "updates','status",
                      "--controller-id", CONTROLLER, PAIR["targetMsiSha256"],
                      PAIR["baseCliSha256"], "OWNER_GENERATION", "RUNTIME_ON",
                      "Get-FileHash", "P 'IN_PROGRESS' 'CHECK_STARTED'",
                      "P 'IN_PROGRESS' 'DOWNLOAD_STARTED'"):
            self.assertIn(token, body)
        self.assertNotIn("updates','install", body)
        self.assertNotIn("msiexec.exe' -ArgumentList", body)
        self.assertLess(len(base64.b64encode(target._bootstrap(CORR, REQUEST, PAIR, SID, FIXTURE).encode("utf-16le"))), 30000)

    def test_readiness_is_inert_and_rejects_forged_ready(self):
        script = target._readiness_script(REQUEST, PAIR, SID)
        self.assertIn("GetOwnerSid", script)
        self.assertIn("activation.port", script)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn("Start-ScheduledTask", script)
        observed = {"version": 1, "code": "READY", "installedVersion": "2.1.19",
                    "productCount": 1, "ownerPid": 3640,
                    "ownerStartedAtUtc": REQUEST["ownerStartedAtUtc"],
                    "controllerId": CONTROLLER, "cliSha256": PAIR["baseCliSha256"],
                    "activeCount": 0}
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(target, "_pair", return_value=PAIR), \
             patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
             patch.object(target.base, "_remote") as remote:
            remote.return_value = json.dumps({"state": "observed", "inventory": observed}).encode()
            admitted = target.readiness(directory, REQUEST)
            self.assertEqual(admitted["state"], "blocked")
            self.assertEqual(admitted["code"], "FIXTURE_ADMISSION_UNAVAILABLE")
            self.assertFalse(admitted["fixtureReady"])
            self.assertFalse(admitted["crossRouteLeaseReady"])
            for changed in ({"ownerPid": 5520}, {"cliSha256": "0" * 64},
                            {"controllerId": "00000000-0000-4000-8000-000000000000"},
                            {"activeCount": 1}):
                remote.return_value = json.dumps({"state": "observed", "inventory": dict(observed, **changed)}).encode()
                self.assertEqual(target.readiness(directory, REQUEST)["state"], "unknown")
            remote.return_value = None
            self.assertEqual(target.readiness(directory, REQUEST)["state"], "unknown")

    def test_ps5_preflight_parses_each_fixed_program_without_running_it(self):
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
             patch.object(target.base, "_remote", return_value=json.dumps({"state": "observed",
                 "inventory": {"version": 1, "code": "OK"}}).encode()) as remote:
            self.assertEqual(target.powershell_preflight(directory, {"host": "archlinux"})["state"], "passed")
            self.assertEqual(remote.call_count, 4)
            self.assertTrue(all(len(call.args[2][3]) < 30000 for call in remote.call_args_list))
            remote.side_effect = [json.dumps({"state": "observed", "inventory": {"version": 1, "code": "OK"}}).encode(),
                                  None]
            self.assertEqual(target.powershell_preflight(directory, {"host": "archlinux"})["state"], "unknown")

    def test_start_never_submits_when_readiness_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(target, "_require_fixture_network_admission"), \
             patch.object(target, "readiness", return_value={"state": "unknown"}), \
             patch.object(target, "_pair") as pair, \
             patch.object(target.base, "_remote") as remote:
            with self.assertRaisesRegex(target.WindowsMsiTargetPrepareError, "not ready"):
                target.start(directory, REQUEST)
            pair.assert_not_called(); remote.assert_not_called()

    def test_missing_network_receipt_blocks_before_guest_or_journal(self):
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(target, "_pair", return_value=PAIR) as pair, \
             patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
             patch.object(target.base, "_require_verified_live_fixture", side_effect=ValueError("unavailable")), \
             patch.object(target, "readiness") as readiness, \
             patch.object(target.base, "_remote") as remote:
            with self.assertRaisesRegex(target.WindowsMsiTargetPrepareError, "FIXTURE_ADMISSION_UNAVAILABLE"):
                target.start(directory, REQUEST)
            readiness.assert_not_called(); pair.assert_called_once(); remote.assert_not_called()
            self.assertIsNone(target._read_intent(Path(directory), CORR))

    def test_verified_server_still_cannot_bypass_missing_target_route_claim(self):
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(target, "_pair", return_value=PAIR), \
             patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
             patch.object(target.base, "_require_verified_live_fixture", return_value=CORR), \
             patch.object(target, "readiness", return_value={"state": "ready"}) as readiness, \
             patch.object(target, "_verified_network_context", return_value=FIXTURE), \
             patch.object(target.base, "_remote") as remote:
            with self.assertRaises(target.base.campaign_lease.Cp117LeaseError):
                target.start(directory, REQUEST)
            readiness.assert_called_once(); remote.assert_not_called()
            self.assertEqual(target._read_intent(Path(directory), CORR)["request"], REQUEST)

    def test_target_reservation_blocks_without_shared_cp117_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(target.WindowsMsiTargetPrepareError, "CP117_CROSS_ROUTE_LEASE_UNAVAILABLE"):
                target._reserve(root, {"request": REQUEST})
            self.assertFalse((root / target._GROUP).exists())

    def test_unknown_submission_is_durable_and_never_replayed(self):
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(target, "_require_fixture_network_admission", return_value=CORR), \
             patch.object(target, "_require_cross_route_lease"), \
             patch.object(target, "_verified_network_context", return_value=FIXTURE), \
             patch.object(target, "readiness", return_value={"state": "ready"}), \
             patch.object(target, "_pair", return_value=PAIR), \
             patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
             patch.object(target.base.campaign_lease, "claim_role", return_value={"state": "role-active"}), \
             patch.object(target.base, "_remote", return_value=None) as remote:
            self.assertEqual(target.start(directory, REQUEST)["state"], "unknown")
            self.assertEqual(target.start(directory, REQUEST)["state"], "unknown")
            self.assertEqual(remote.call_count, 1)
            self.assertEqual(target._read_intent(Path(directory), CORR)["request"], REQUEST)

    def test_running_requires_exact_live_task_and_bounded_intent_age(self):
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                "expectedSid": SID, "commandSha256": "0" * 64,
                "createdAtUtc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")}
            with patch.object(target, "_require_cross_route_lease"):
                target._reserve(root, record)
            with patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
                 patch.object(target.base, "_remote") as remote:
                remote.return_value = json.dumps({"state": "running", "correlationId": CORR,
                                                  "taskState": "Running"}).encode()
                self.assertEqual(target.status(root, {"correlationId": CORR})["state"], "running")
                for task_state in ("Ready", "Disabled", "Unknown", None):
                    remote.return_value = json.dumps({"state": "running", "correlationId": CORR,
                                                      "taskState": task_state}).encode()
                    self.assertEqual(target.status(root, {"correlationId": CORR})["state"], "unknown")
                stale = datetime.now(timezone.utc) - timedelta(minutes=26)
                record["createdAtUtc"] = stale.isoformat(timespec="seconds").replace("+00:00", "Z")
                path = target._intent_path(root, CORR)
                path.write_text(json.dumps(record) + "\n")
                remote.return_value = json.dumps({"state": "running", "correlationId": CORR,
                                                  "taskState": "Running"}).encode()
                self.assertEqual(target.status(root, {"correlationId": CORR})["state"], "unknown")

    def test_guest_task_probe_rejects_stopped_or_wrong_task(self):
        # Exercise the same decision function embedded in the QGA observer.
        body = target._REMOTE_STATUS.split("def live_task():\n", 1)[1].split("def running_or_unknown():", 1)[0]
        namespace = {"base64": base64, "hashlib": hashlib, "json": json,
                     "decode": lambda raw: raw.decode(), "corr": CORR}
        script = target._task_probe_script(CORR)
        namespace["probe_encoded"] = base64.b64encode(script.encode("utf-16le")).decode()
        namespace["probe_hash"] = hashlib.sha256(script.encode("utf-16le")).hexdigest()
        def set_state(state, task_name="VpnControlMcpTarget-" + CORR):
            reply = json.dumps({"version": 1, "taskName": task_name, "state": state}).encode()
            def call(_sock, command, _args):
                if command == "guest-exec": return {"pid": 17}
                return {"exited": True, "exitcode": 0, "out-data": base64.b64encode(reply).decode()}
            namespace["call"] = call
        namespace["sock"] = "/qga.sock"
        exec("def live_task():\n" + body, namespace)
        set_state("Running")
        self.assertTrue(namespace["live_task"]())
        set_state("Ready")
        self.assertFalse(namespace["live_task"]())
        set_state("Running", "VpnControlMcpTarget-" + CONTROLLER)
        self.assertFalse(namespace["live_task"]())

    def test_terminal_qga_result_is_durable_after_one_shot_pid_reap(self):
        body = target._REMOTE_STATUS.split("def terminal_or_live(stage,child):\n", 1)[1].split("try:\n stage=os.path.join", 1)[0]
        calls = []
        def call(_sock, command, args):
            calls.append((command, args))
            if len(calls) > 1:
                raise AssertionError("QGA terminal PID was queried after reap")
            return {"exited": True, "exitcode": 0, "out-data": base64.b64encode(b'{"triggered":true}').decode()}
        namespace = {"os": os, "stat": stat, "fcntl": fcntl, "json": json,
                     "sock": "/qga.sock", "call": call}
        exec("def terminal_or_live(stage,child):\n" + body, namespace)
        with tempfile.TemporaryDirectory() as directory:
            first = namespace["terminal_or_live"](directory, 991)
            self.assertEqual(first["exitcode"], 0)
            self.assertEqual(namespace["terminal_or_live"](directory, 991), first)
            self.assertEqual(len(calls), 1)
            journal = Path(directory) / "bootstrap-terminal.json"
            self.assertEqual(json.loads(journal.read_text()), first)
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)

    def test_status_rejects_forged_ready_cache_and_owner(self):
        class Guest:
            fixture_transfer_root = Path("/private/cp117")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(target, "_require_cross_route_lease"):
                target._reserve(root, {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                    "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                    "expectedSid": SID, "commandSha256": "0" * 64})
            payload = {"version": 1, "correlationId": CORR, "stage": "READBACK", "result": "PASSED",
                       "code": "READY", "originalSid": SID, "sessionId": 1, "limited": True,
                       "controllerId": CONTROLLER, "ownerPid": 3640,
                       "checked": {"code": "OK", "availableVersion": "2.2.0", "controllerId": CONTROLLER},
                       "downloaded": {"code": "OK", "controllerId": CONTROLLER},
                       "ready": {"phase": "ready", "availableVersion": "2.2.0",
                                 "downloadedBytes": 123456, "totalBytes": 123456,
                                 "controllerId": CONTROLLER}, "cacheSha256": PAIR["targetMsiSha256"]}
            with patch.object(target.base, "_descriptor", return_value=(object(), Guest(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, SID))), \
                 patch.object(target.base, "_remote") as remote:
                remote.return_value = json.dumps({"state": "observed", "correlationId": CORR, "result": payload}).encode()
                observed = target.status(root, {"correlationId": CORR})
                self.assertEqual(observed["result"], "PASSED")
                self.assertEqual(observed["evidenceScope"], "completion-time")
                self.assertFalse(observed["currentReady"])
                remote.return_value = json.dumps({"state": "observed", "correlationId": CORR,
                    "result": dict(payload, result="IN_PROGRESS")}).encode()
                self.assertEqual(target.status(root, {"correlationId": CORR})["state"], "unknown")
                for change in ({"cacheSha256": "0" * 64}, {"ownerPid": 5520},
                               {"ready": dict(payload["ready"], phase="downloaded")},
                               {"checked": dict(payload["checked"], availableVersion="2.3.0")},
                               {"downloaded": dict(payload["downloaded"], controllerId=CORR)},
                               {"originalSid": "S-1-5-18"}):
                    remote.return_value = json.dumps({"state": "observed", "correlationId": CORR,
                        "result": dict(payload, **change)}).encode()
                    self.assertEqual(target.status(root, {"correlationId": CORR})["state"], "unknown")


if __name__ == "__main__":
    unittest.main()

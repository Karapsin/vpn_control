from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from agent_tools import windows_cp117_lease as lease


def identity(lease_id: str | None = None) -> dict:
    return {"host": "archlinux", "environment": "windows-cp117",
            "leaseId": lease_id or str(uuid.uuid4()), "operator": "windows-owner",
            "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
            "baseMsiArtifactId": "sha256-" + "c" * 64,
            "targetMsiArtifactId": "sha256-" + "d" * 64,
            "socketPath": "/owned/cp117.qga", "qemuPid": 4321, "startTicks": 98765}


def remote_at(root: Path):
    transfer = root / "remote"
    transfer.mkdir(mode=0o700, exist_ok=True)
    prefix = "import base64,hashlib,json,os,secrets,stat,sys\n" \
             "def live(sock,pid,ticks):return sock=='/owned/cp117.qga' and pid=='4321' and ticks=='98765'\n"

    def remote(action: str, payload: dict) -> bytes:
        args = lease.remote_arguments(transfer, action, payload)
        run = subprocess.run([sys.executable, "-c", prefix + lease._REMOTE_BODY, *args],
                             capture_output=True, timeout=10, check=False)
        if run.returncode:
            raise AssertionError(run.stderr.decode(errors="replace"))
        return run.stdout

    return remote


class Cp117CampaignLeaseTests(unittest.TestCase):
    def test_native_route_guard_requires_exact_remote_claim_without_creating_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            bound = dict(identity(), operator="windows-base")
            corr = str(uuid.uuid4())
            def observe(role: str, source: str = bound["sourceSha"]) -> bool:
                args = [str(root), "windows-cp117", bound["leaseId"], role, corr, source,
                        bound["fixtureReceiptArtifactId"], bound["baseMsiArtifactId"],
                        bound["targetMsiArtifactId"], bound["socketPath"],
                        str(bound["qemuPid"]), str(bound["startTicks"])]
                script = lease.remote_role_guard() + "\ntry:\n require_campaign_role(*sys.argv[1:]);print('admitted')\nexcept Exception:print('unknown')\n"
                run = subprocess.run([sys.executable, "-c", "import sys\n" + script, *args],
                                     capture_output=True, timeout=5, check=True)
                return run.stdout.strip() == b"admitted"
            self.assertFalse(observe("public"))
            self.assertEqual(list(root.iterdir()), [])
            group = root / "windows-cp117/windows-cp117-campaign"
            group.mkdir(parents=True, mode=0o700)
            group.parent.chmod(0o700)
            (group / ".environment.lock").write_bytes(b"")
            (group / ".environment.lock").chmod(0o600)
            record = {"version": 1, "sequence": 3, "state": "role-active", "role": "public",
                      "correlationId": corr, "server": "live", "credentials": "ready",
                      "lastEvidenceSha256": "e" * 64, "lastOutcome": "succeeded", "identity": bound}
            (group / "active.json").write_text(json.dumps(record))
            (group / "active.json").chmod(0o600)
            self.assertTrue(observe("public"))
            self.assertFalse(observe("target"))
            self.assertFalse(observe("public", "f" * 40))
            (group / "active.json").write_text(json.dumps({key: value for key, value in record.items()
                                                           if key != "credentials"}))
            self.assertFalse(observe("public"))
            (group / "active.json").write_text(json.dumps(record))
            self.assertEqual(record, json.loads((group / "active.json").read_text()))

    def test_remote_status_never_creates_missing_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity()
            desired = {"version": 1, "identity": bound, "sequence": 0, "state": "active",
                       "role": None, "correlationId": None, "server": "stopped", "credentials": "absent",
                       "lastEvidenceSha256": None, "lastOutcome": None}
            for action in ("status", "finalize"):
                receipt = json.loads(remote(action, {"action": action, "desired": desired,
                                                     "priorSha256": None}))
                self.assertEqual(receipt, {"version": 1, "state": "unknown"})
            self.assertEqual(list((root / "remote").iterdir()), [])

    def test_conflicting_active_and_closed_records_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, remote)
            remote_group = root / "remote/windows-cp117/windows-cp117-campaign"
            active = remote_group / "active.json"
            closed = remote_group / (lease_id + ".closed.json")
            closed.write_bytes(active.read_bytes()); closed.chmod(0o600)
            desired = json.loads(active.read_text())
            receipt = json.loads(remote("status", {"action": "status", "desired": desired,
                                                    "priorSha256": None}))
            self.assertEqual(receipt, {"version": 1, "state": "unknown"})
            self.assertEqual(active.read_bytes(), closed.read_bytes())

            local_group = root / ".rag_index/windows-cp117-campaign"
            local_closed = local_group / (lease_id + ".closed.json")
            local_closed.write_bytes((local_group / "active.json").read_bytes()); local_closed.chmod(0o600)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.inspect(root, lease_id)

    def test_one_campaign_serializes_routes_and_preserves_server_role(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            self.assertEqual(lease.begin(root, bound, remote)["state"], "active")
            base_corr = str(uuid.uuid4())
            self.assertEqual(lease.claim_role(root, lease_id, "base", base_corr, remote)["state"], "role-active")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "public", str(uuid.uuid4()), remote)
            lease.finish_role(root, lease_id, "base", base_corr, "e" * 64, "succeeded", remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "target", str(uuid.uuid4()), remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "server-start", str(uuid.uuid4()), remote)
            credentials_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "credentials", credentials_corr, remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "server-start", str(uuid.uuid4()), remote)
            lease.finish_role(root, lease_id, "credentials", credentials_corr, "4" * 64, "succeeded", remote)
            server_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "server-start", server_corr, remote)
            lease.finish_role(root, lease_id, "server-start", server_corr, "f" * 64, "succeeded", remote)
            self.assertEqual(lease.inspect(root, lease_id)["server"], "live")
            owner_network_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "owner-network", owner_network_corr, remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "network-probe", str(uuid.uuid4()), remote)
            lease.finish_role(root, lease_id, "owner-network", owner_network_corr,
                              "9" * 64, "succeeded", remote)
            probe_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "network-probe", probe_corr, remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "public", str(uuid.uuid4()), remote)
            lease.finish_role(root, lease_id, "network-probe", probe_corr, "0" * 64, "succeeded", remote)
            target_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "target", target_corr, remote)
            lease.finish_role(root, lease_id, "target", target_corr, "1" * 64, "succeeded", remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "credentials-cleanup", str(uuid.uuid4()), remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.close(root, lease_id, {}, remote)
            stop_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "server-stop", stop_corr, remote)
            lease.finish_role(root, lease_id, "server-stop", stop_corr, "2" * 64, "succeeded", remote)
            cleanup_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "credentials-cleanup", cleanup_corr, remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "server-start", str(uuid.uuid4()), remote)
            lease.finish_role(root, lease_id, "credentials-cleanup", cleanup_corr, "5" * 64, "succeeded", remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "server-start", str(uuid.uuid4()), remote)
            proof = {"guestGeneration": {"socketPath": bound["socketPath"], "qemuPid": bound["qemuPid"],
                                         "startTicks": bound["startTicks"]},
                     "serverStopped": True, "credentialsCleaned": True, "protectedJobsTerminalCleaned": True,
                     "activeInstallerProcessesAbsent": True, "cleanupReceiptSha256": "3" * 64}
            self.assertEqual(lease.close(root, lease_id, proof, remote)["state"], "closed")
            self.assertEqual(lease.inspect(root, lease_id)["state"], "closed")
            self.assertEqual(lease.reconcile(root, lease_id, remote)["state"], "closed")
            self.assertTrue((root / ".rag_index/windows-cp117-campaign" /
                             (lease_id + ".closed.json")).exists())

    def test_close_rejects_changed_terminal_record_before_remote_dispatch(self):
        """A later role finish cannot close on an older retirement proof."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            self.assertEqual("active", lease.begin(root, bound, remote)["state"])
            local = root / ".rag_index/windows-cp117-campaign/active.json"
            old_active = json.loads(local.read_text())
            correlation = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "stage", correlation, remote)
            lease.finish_role(root, lease_id, "stage", correlation, "e" * 64, "failed-cleaned", remote)
            changed = json.loads(local.read_text())
            self.assertNotEqual(old_active, changed)
            proof = {"guestGeneration": {"socketPath": bound["socketPath"],
                     "qemuPid": bound["qemuPid"], "startTicks": bound["startTicks"]},
                     "serverStopped": True, "credentialsCleaned": True,
                     "protectedJobsTerminalCleaned": True,
                     "activeInstallerProcessesAbsent": True, "cleanupReceiptSha256": "f" * 64}
            with self.assertRaises(lease.Cp117LeaseError):
                lease.close(root, lease_id, proof, remote, expected_current=old_active)
            self.assertEqual(changed, json.loads(local.read_text()))
            self.assertEqual("active", lease.inspect(root, lease_id)["state"])

    def test_lost_remote_response_is_sticky_across_restart_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); actual = remote_at(root); bound = identity(); calls = []

            def lost(action, payload):
                calls.append(action)
                actual(action, payload)
                return None

            result = lease.begin(root, bound, lost)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])
            self.assertEqual(lease.inspect(root, bound["leaseId"])["state"], "pending-remote")
            self.assertEqual(lease.reconcile(root, bound["leaseId"], actual)["state"], "active")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.begin(root, bound, actual)
            role = str(uuid.uuid4())
            self.assertEqual(lease.claim_role(root, bound["leaseId"], "base", role, actual)["state"], "role-active")
            self.assertEqual(calls, ["reserve"])

    def test_lost_remote_role_response_recovers_by_read_only_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); actual = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, actual)
            role = str(uuid.uuid4()); calls = []

            def lost(action, payload):
                calls.append(action)
                actual(action, payload)
                return None

            self.assertEqual(lease.claim_role(root, lease_id, "base", role, lost)["state"], "unknown")
            self.assertEqual(lease.inspect(root, lease_id)["state"], "pending-role")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "public", str(uuid.uuid4()), actual)
            self.assertEqual(lease.reconcile(root, lease_id, actual)["state"], "role-active")
            self.assertEqual(calls, ["claim"])

    def test_failed_server_start_stays_serialized_until_verified_failed_cleaned_finish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, remote)
            credentials_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "credentials", credentials_corr, remote)
            lease.finish_role(root, lease_id, "credentials", credentials_corr, "a" * 64, "succeeded", remote)
            server_corr = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "server-start", server_corr, remote)
            self.assertEqual(lease.inspect(root, lease_id)["server"], "starting")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "server-stop", str(uuid.uuid4()), remote)
            observed = lease.finish_role(root, lease_id, "server-start", server_corr,
                                         "b" * 64, "failed-cleaned", remote)
            self.assertEqual(observed["state"], "active")
            self.assertEqual(lease.inspect(root, lease_id)["server"], "stopped")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "server-stop", str(uuid.uuid4()), remote)

    def test_unknown_cleaned_is_reserved_for_the_base_role_after_terminal_cleanup_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, remote)
            correlation = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "base", correlation, remote)
            self.assertEqual(lease.finish_role(root, lease_id, "base", correlation,
                                               "d" * 64, "unknown-cleaned", remote)["state"], "active")
            self.assertEqual(lease.inspect(root, lease_id)["state"], "active")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.finish_role(root, lease_id, "base", correlation, "e" * 64,
                                  "unknown-cleaned", remote)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, remote)
            correlation = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "stage", correlation, remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.finish_role(root, lease_id, "stage", correlation, "f" * 64,
                                  "unknown-cleaned", remote)

    def test_remote_finish_rejects_unknown_cleaned_for_non_base_role(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, remote)
            correlation = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "stage", correlation, remote)
            old = json.loads((root / "remote/windows-cp117/windows-cp117-campaign/active.json").read_text())
            desired = dict(old, sequence=old["sequence"] + 1, state="active", role=None,
                           correlationId=None, lastEvidenceSha256="f" * 64,
                           lastOutcome="unknown-cleaned")
            receipt = json.loads(remote("finish", {"action": "finish", "desired": desired,
                                                    "priorSha256": lease._digest(old)}))
            self.assertEqual(receipt, {"version": 1, "state": "unknown"})

    def test_owner_network_claim_requires_live_server_and_ready_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "owner-network", str(uuid.uuid4()), remote)
            credentials = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "credentials", credentials, remote)
            lease.finish_role(root, lease_id, "credentials", credentials, "1" * 64, "succeeded", remote)
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "owner-network", str(uuid.uuid4()), remote)
            server = str(uuid.uuid4())
            lease.claim_role(root, lease_id, "server-start", server, remote)
            lease.finish_role(root, lease_id, "server-start", server, "2" * 64, "succeeded", remote)
            owner = str(uuid.uuid4())
            self.assertEqual(lease.claim_role(root, lease_id, "owner-network", owner, remote)["state"],
                             "role-active")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.claim_role(root, lease_id, "server-stop", str(uuid.uuid4()), remote)
            lease.finish_role(root, lease_id, "owner-network", owner, "3" * 64,
                              "failed-cleaned", remote)
            self.assertEqual(lease.inspect(root, lease_id)["server"], "live")

    def test_two_route_campaigns_race_for_one_local_and_remote_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); remote = remote_at(root)
            barrier = threading.Barrier(2); results = []

            def start(bound):
                barrier.wait()
                try: results.append(lease.begin(root, bound, remote)["state"])
                except lease.Cp117LeaseError: results.append("blocked")

            threads = [threading.Thread(target=start, args=(identity(),)) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(timeout=15)
            self.assertEqual(sorted(results), ["active", "blocked"])

    def test_changed_guest_generation_never_admits_remote_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bound = dict(identity(), startTicks=12345)
            result = lease.begin(root, bound, remote_at(root))
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])
            self.assertEqual(lease.reconcile(root, bound["leaseId"], remote_at(root))["state"], "unknown")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.begin(root, identity(), remote_at(root))

    def test_lost_close_response_requires_remote_closed_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); actual = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, actual)
            proof = {"guestGeneration": {"socketPath": bound["socketPath"], "qemuPid": bound["qemuPid"],
                                         "startTicks": bound["startTicks"]},
                     "serverStopped": True, "credentialsCleaned": True, "protectedJobsTerminalCleaned": True,
                     "activeInstallerProcessesAbsent": True, "cleanupReceiptSha256": "6" * 64}

            def lost(action, payload):
                actual(action, payload)
                return None

            self.assertEqual(lease.close(root, lease_id, proof, lost)["state"], "unknown")
            self.assertEqual(lease.inspect(root, lease_id)["state"], "pending-close")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.begin(root, identity(), actual)
            self.assertEqual(lease.reconcile(root, lease_id, actual)["state"], "closed")
            self.assertEqual(lease.begin(root, identity(), actual)["state"], "active")

    def test_interrupted_close_at_remote_and_local_rename_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); actual = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, actual)
            proof = {"guestGeneration": {"socketPath": bound["socketPath"], "qemuPid": bound["qemuPid"],
                                         "startTicks": bound["startTicks"]},
                     "serverStopped": True, "credentialsCleaned": True, "protectedJobsTerminalCleaned": True,
                     "activeInstallerProcessesAbsent": True, "cleanupReceiptSha256": "7" * 64}

            def interrupted_remote_close(action, payload):
                self.assertEqual(action, "close")
                remote_active = root / "remote/windows-cp117/windows-cp117-campaign/active.json"
                remote_active.write_text(json.dumps(payload["desired"], sort_keys=True) + "\n")
                remote_active.chmod(0o600)
                return None

            self.assertEqual(lease.close(root, lease_id, proof, interrupted_remote_close)["state"], "unknown")
            remote_group = root / "remote/windows-cp117/windows-cp117-campaign"
            self.assertTrue((remote_group / "active.json").exists())
            self.assertFalse((remote_group / (lease_id + ".closed.json")).exists())
            self.assertEqual(lease.reconcile(root, lease_id, actual)["state"], "closed")
            self.assertFalse((remote_group / "active.json").exists())
            self.assertTrue((remote_group / (lease_id + ".closed.json")).exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); actual = remote_at(root); bound = identity(); lease_id = bound["leaseId"]
            lease.begin(root, bound, actual)
            def lost(action, payload):
                actual(action, payload)
                return None
            lease.close(root, lease_id, proof | {"guestGeneration": {
                "socketPath": bound["socketPath"], "qemuPid": bound["qemuPid"],
                "startTicks": bound["startTicks"]}}, lost)
            local_group = root / ".rag_index/windows-cp117-campaign"
            active = local_group / "active.json"
            pending = json.loads(active.read_text())
            active.write_text(json.dumps(dict(pending, state="closed"), sort_keys=True) + "\n")
            active.chmod(0o600)
            self.assertEqual(lease.reconcile(root, lease_id, actual)["state"], "closed")
            self.assertFalse(active.exists())

    def test_legacy_terminal_requires_exact_cleanup_and_keeps_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = {"correlationId": "99126312-977f-4a61-a9ef-fb6884d2d26f",
                     "guestGeneration": {"socketPath": "/owned/cp117.qga", "qemuPid": 4321, "startTicks": 98765},
                     "terminalJobId": "9107428f-9c80-4284-9f4e-926350105a59",
                     "terminalPhase": "Failed", "cleanupCode": "OK",
                     "activeInstallerProcessesAbsent": True, "evidenceSha256": "4" * 64}
            with self.assertRaises(lease.Cp117LeaseError):
                lease.attest_legacy_closed(root, dict(proof, terminalPhase="Installing"))
            with self.assertRaises(lease.Cp117LeaseError):
                lease.attest_legacy_closed(root, dict(proof, activeInstallerProcessesAbsent=False))
            self.assertEqual(lease.attest_legacy_closed(root, proof)["state"], "closed")
            self.assertEqual(lease.attest_legacy_closed(root, proof)["state"], "closed")
            with self.assertRaises(lease.Cp117LeaseError):
                lease.attest_legacy_closed(root, dict(proof, evidenceSha256="5" * 64))
            self.assertEqual(json.loads((root / ".rag_index/windows-cp117-campaign" /
                (proof["correlationId"] + ".legacy-closed.json")).read_text()), proof)
            self.assertFalse((root / ".rag_index/windows-cp117-campaign/active.json").exists())
            self.assertEqual(lease.inspect(root, str(uuid.uuid4()))["state"], "unknown")
            self.assertFalse((root / "remote").exists())


if __name__ == "__main__": unittest.main()

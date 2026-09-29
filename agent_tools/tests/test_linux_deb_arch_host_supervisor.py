"""Fixed host supervisor admission and no-replay transport contracts."""
from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
import uuid

from agent_tools import linux_deb_arch_acceptance as acceptance
from agent_tools import linux_deb_arch_host_supervisor as host


class HostSupervisorTest(unittest.TestCase):
    def fixture(self):
        request = {"profile": "package-update", "distribution": "ubuntu", "correlationId": str(uuid.uuid4()),
                   "sourceSha": "a" * 40, "artifactIds": {key: "sha256-" + str(index) * 64 for index, key
                                                      in enumerate(sorted(acceptance._ARTIFACT_KEYS), 1)}}
        intent = acceptance.Intent.parse(request)
        guest = {"guestRole": intent.guest_role, "sshPort": intent.guest_port,
                 "tree": "/home/kardinal/vpn-control-install-vm-parity-ubuntu-update",
                 "qemuPid": 123, "qemuStartTicks": 456, "diskDevice": 7, "diskInode": 8}
        admission = {"ready": True, "guestRole": intent.guest_role, "sourceSha": intent.source_sha,
                     "harnessSha256": "e" * 64,
                     "fixture": {"sourceFingerprint": "b" * 64, "targetVersion": "2.2.0"},
                     "guest": guest,
                     "preparation": {"stage": "/var/lib/vpn-control-parity/ubuntu-update",
                                     "fixture": {"trustStoreSha256": "c" * 64}}}
        worker = {"profile": intent.profile, "distribution": intent.distribution,
                  "guestRole": intent.guest_role, "correlationId": intent.correlation_id,
                  "sourceSha": intent.source_sha, "sourceFingerprint": "b" * 64,
                  "targetVersion": "2.2.0",
                  "targetSha256": intent.artifact_ids["targetPackage"].removeprefix("sha256-"),
                  "fixtureReceiptArtifactId": intent.artifact_ids["fixtureReceipt"],
                  "harnessSha256": "e" * 64, "trustStoreSha256": "c" * 64}
        admission["preparation"]["workerIntentSha256"] = hashlib.sha256(
            (json.dumps(worker, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
        return intent, admission

    def test_remote_programs_compile_with_fixed_roles(self):
        for source in (host._SUBMIT, host._STATUS, host._WORKER):
            program = host._program(source)
            compile(program, "fixed-host-program", "exec")
            self.assertIn("ubuntu-fresh", program)
            self.assertNotIn("vpn-control-install-vm-9540bc92", program)

    def test_submit_uses_exact_fixed_role_and_worker_intent(self):
        intent, admission = self.fixture()
        observed = []
        supervisor = host.FixedHostSupervisor(tempfile.gettempdir(), observer=lambda *args: {
            "ready": True, "ownerRuntimeOff": True, "packageProcessesOff": True,
            "protectedJobsTerminal": True, "profileUnused": True})
        def remote(program, *args):
            observed.append((program, args))
            return {"state": "submitted", "correlationId": intent.correlation_id}
        supervisor._remote = remote
        self.assertEqual("submitted", supervisor.submit(intent, admission)["state"])
        self.assertEqual(1, len(observed))
        metadata = json.loads(observed[0][1][0])
        self.assertEqual(intent.guest_role, metadata["guestRole"])
        self.assertEqual(intent.artifact_ids, metadata["artifactIds"])
        self.assertEqual(intent.artifact_ids["fixtureReceipt"],
                         metadata["workerIntent"]["fixtureReceiptArtifactId"])
        self.assertEqual("c" * 64, metadata["workerIntent"]["trustStoreSha256"])
        self.assertEqual("e" * 64, metadata["workerIntent"]["harnessSha256"])

    def test_failed_live_recheck_never_contacts_remote_submit(self):
        intent, admission = self.fixture()
        supervisor = host.FixedHostSupervisor(Path(tempfile.gettempdir()), observer=lambda *args: {"ready": False})
        def unexpected(*args):
            raise AssertionError("remote submit must not run")
        supervisor._remote = unexpected
        self.assertEqual("unknown", supervisor.submit(intent, admission)["state"])

    def test_package_process_seen_at_submit_never_contacts_remote(self):
        intent, admission = self.fixture()
        supervisor = host.FixedHostSupervisor(Path(tempfile.gettempdir()), observer=lambda *args: {
            "ready": True, "ownerRuntimeOff": True, "packageProcessesOff": False,
            "protectedJobsTerminal": True, "profileUnused": True})
        supervisor._remote = lambda *args: self.fail("package process must block submit")
        self.assertEqual("unknown", supervisor.submit(intent, admission)["state"])

    def test_changed_worker_intent_never_burns_host_claim(self):
        intent, admission = self.fixture()
        admission["preparation"]["workerIntentSha256"] = "0" * 64
        supervisor = host.FixedHostSupervisor(Path(tempfile.gettempdir()), observer=lambda *args: {
            "ready": True, "ownerRuntimeOff": True, "packageProcessesOff": True,
            "protectedJobsTerminal": True, "profileUnused": True})
        supervisor._remote = lambda *args: self.fail("mismatched worker intent must block submit")
        self.assertEqual("unknown", supervisor.submit(intent, admission)["state"])

    def test_status_rejects_symlink_job_parent_before_result_read(self):
        intent, admission = self.fixture()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            parent = Path(temp)
            root = parent / "jobs"
            root.mkdir(mode=0o700)
            actual = parent / "actual"
            actual.mkdir(mode=0o700)
            (root / intent.correlation_id).symlink_to(actual, target_is_directory=True)
            for path, value in ((root / (intent.guest_role + ".claim"),
                                 {"guestRole": intent.guest_role, "correlationId": intent.correlation_id}),
                                (actual / "intent.json", {"guestRole": intent.guest_role,
                                                          "correlationId": intent.correlation_id}),
                                (actual / "result.json", {"state": "terminal"})):
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            program = host._program(host._STATUS).replace(
                "'/home/kardinal/.vpn-control-parity-jobs'", repr(str(root)))
            result = subprocess.run([sys.executable, "-c", program, intent.guest_role,
                                     intent.correlation_id], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual("", result.stdout)

    def test_submit_rechecks_qmp_before_creating_host_claim(self):
        intent, admission = self.fixture()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            parent = Path(temp)
            prefix = str(parent / "vpn-control-install-vm-parity-")
            tree = Path(prefix + intent.guest_role)
            tree.mkdir()
            disk = tree / "task.qcow2"
            disk.write_bytes(b"disk")
            jobs = parent / "jobs"
            generation = {"pid": os.getpid(), "startTicks": 456,
                          "diskDevice": disk.stat().st_dev, "diskInode": disk.stat().st_ino}
            metadata = {"guestRole": intent.guest_role, "guestPort": intent.guest_port,
                        "tree": str(tree), "correlationId": intent.correlation_id,
                        "guestGeneration": generation, "workerIntent": {},
                        "sourceSha": intent.source_sha, "artifactIds": intent.artifact_ids}
            program = host._program(host._SUBMIT)
            program = program.replace("'/home/kardinal/vpn-control-install-vm-parity-'", repr(prefix))
            program = program.replace("'/home/kardinal/.vpn-control-parity-jobs'", repr(str(jobs)))
            start = program.index("def ticks(pid):")
            end = program.index("disk=tree+", start)
            program = program[:start] + "def ticks(pid):return 456\n" + program[end:]
            result = subprocess.run([sys.executable, "-c", program, json.dumps(metadata)],
                                    capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((jobs / (intent.guest_role + ".claim")).exists())


if __name__ == "__main__":
    unittest.main()

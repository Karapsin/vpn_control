"""Causal admission tests for the read-only Secure Boot clone preflight."""
from __future__ import annotations

import json
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_vm_secureboot_clone as subject


REQUEST = {"host": "archlinux", "ownerPid": subject.OWNER_PID,
           "ownerStartTicks": subject.OWNER_TICKS,
           "baselineReservationId": subject.BASELINE_RESERVATION, "timeoutSeconds": 30}


def payload() -> dict:
    return {"schemaVersion": 1, "host": "archlinux", "ownerPid": subject.OWNER_PID,
            "ownerStartTicks": subject.OWNER_TICKS, "sourceDisk": subject.SOURCE,
            "cloneRoot": subject.CLONE_ROOT,
            "sourceHolders": [{"pid": subject.OWNER_PID, "startTicks": subject.OWNER_TICKS}],
            "cloneRootAbsent": True, "codeSha256": subject.CODE_SHA256, "codeSizeBytes": 3653632,
            "varsSha256": subject.VARS_SHA256, "varsSizeBytes": 540672,
            "binaries": {"qemu-system-x86_64": True, "swtpm": True,
                         "swtpm_setup": True, "virt-fw-vars": False},
            "packages": {"edk2-ovmf": True, "swtpm": True, "virt-firmware": False},
            "kvmAvailable": True, "availableMemoryKiB": 30000000,
            "freeDiskKiB": 50000000}


class WindowsVmSecurebootCloneTest(unittest.TestCase):
    def test_missing_virt_fw_vars_and_live_source_block_clone(self):
        result = subject.classify(payload(), baseline_reservation_pinned=True)
        self.assertEqual(result["state"], "blocked")
        self.assertIn("virt-fw-vars-unavailable", result["missing"])
        self.assertIn("source-running", result["missing"])
        self.assertIn("clone-reservation-absent", result["missing"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_missing_owner_resource_pin_and_target_isolation_fail_closed(self):
        for mutation in ({"ownerPid": 55}, {"sourceDisk": "/home/kardinal/CP117/disk.qcow2"},
                         {"cloneRoot": subject.SOURCE.rsplit("/", 1)[0]},
                         {"sourceHolders": [{"pid": 88, "startTicks": 11}]}):
            with self.subTest(mutation=mutation):
                self.assertEqual(subject.classify({**payload(), **mutation}, baseline_reservation_pinned=True)["state"], "unknown")
        result = subject.classify(payload(), baseline_reservation_pinned=False)
        self.assertIn("baseline-reservation-unverified", result["missing"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_clone_root_exists_and_capacity_deficits_block(self):
        value = payload()
        value.update(cloneRootAbsent=False, availableMemoryKiB=0, freeDiskKiB=0)
        missing = subject.classify(value, baseline_reservation_pinned=True)["missing"]
        self.assertIn("clone-root-exists", missing)
        self.assertIn("memory-headroom", missing)
        self.assertIn("disk-headroom", missing)

    def test_exact_private_baseline_reservation_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / ".rag_index/native-environments"
            state_dir.mkdir(parents=True)
            path = state_dir / "reservations.json"
            record = {"id": subject.BASELINE_RESERVATION, "hostAlias": "archlinux",
                      "environment": "windows-vm-baseline-20260929", "operator": "windows-baseline",
                      "requestedMemoryBytes": subject.MEMORY_KIB * 1024,
                      "allocationState": "pending"}
            path.write_text(json.dumps({"version": 1, "reservations": [record]}))
            path.chmod(0o600)
            self.assertTrue(subject._baseline_reservation(root))
            path.write_text(json.dumps({"version": 1, "reservations": [{**record, "hostAlias": "other"}]}))
            self.assertFalse(subject._baseline_reservation(root))
            path.write_text(json.dumps({"version": 1, "reservations": [record]}))
            path.chmod(0o644)
            self.assertFalse(subject._baseline_reservation(root))

    def test_remote_owner_rejects_unrelated_disk_despite_matching_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            pid = proc / "77"
            (pid / "fd").mkdir(parents=True)
            disk = root / "source.qcow2"
            disk.write_bytes(b"qcow2")
            (pid / "fd/5").symlink_to(disk)
            (pid / "fd/6").symlink_to("socket:[55]")
            (pid / "stat").write_text("77 (qemu-system-x86) S " + "0 " * 18 + "123 0\n")
            qmp = root / "qmp.sock"
            (proc / "net").mkdir()
            (proc / "net/unix").write_text("Num RefCount Protocol Flags Type St Inode Path\n"
                                          + "00000000: 00000002 00000000 00010000 0001 01 55 "
                                          + str(qmp) + "\n")
            source = subject._REMOTE.split("def source_holders", 1)[0]
            source = source.replace("PID=3369984;TICKS=45177745", "PID=77;TICKS=123")
            source = source.replace("/proc", str(proc))
            source = source.replace(subject.SOURCE, str(disk)).replace(subject.QMP, str(qmp))
            scope: dict = {}
            exec(source, scope)
            unrelated = root / "unrelated.qcow2"
            unrelated.write_bytes(b"qcow2")
            (pid / "cmdline").write_bytes(("qemu-system-x86_64\0-drive\0file=" + str(unrelated)
                                            + ",if=virtio,format=qcow2\0-qmp\0unix:" + str(qmp)
                                            + ",server=on,wait=off\0").encode())
            with self.assertRaises(ValueError):
                scope["owner"]()
            (pid / "cmdline").write_bytes(("qemu-system-x86_64\0-drive\0file=" + str(disk)
                                            + ",if=virtio,format=qcow2\0-qmp\0unix:" + str(qmp)
                                            + ",server=on,wait=off\0").encode())
            self.assertEqual(scope["owner"](), (disk.stat().st_dev, disk.stat().st_ino))
            (pid / "fd/6").unlink()
            (pid / "fd/6").symlink_to("socket:[other]")
            with self.assertRaises(ValueError):
                scope["owner"]()

    def test_invalid_request_cannot_load_transport_or_dispatch(self):
        with mock.patch.object(subject.ssh_transport, "load_config") as load:
            for changed in ({"host": "other"}, {"ownerPid": 1}, {"ownerStartTicks": 1},
                            {"baselineReservationId": "wrong"}, {"timeoutSeconds": 100}, {"extra": "x"}):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    subject.preflight(Path.cwd(), {**REQUEST, **changed})
            load.assert_not_called()

    def test_remote_source_holder_failure_emits_fixed_phase_without_host_details(self):
        script = subject._REMOTE.replace("identity=owner();stage='source-holders';holders=source_holders(identity)",
                                         "identity=(1,1);stage='source-holders';raise PermissionError('private host path')")
        self.assertNotEqual(script, subject._REMOTE)
        output = io.StringIO()
        with redirect_stdout(output):
            exec(script, {})
        raw = json.loads(output.getvalue())
        self.assertEqual(raw["failurePhase"], "source-holders")
        self.assertNotIn("private host path", output.getvalue())
        result = subject.classify(raw, baseline_reservation_pinned=True)
        self.assertEqual(result, {"state": "unknown", "failurePhase": "source-holders",
                                  "nativeActionAllowed": False})
        raw["failurePhase"] = "arbitrary-host-detail"
        self.assertEqual(subject.classify(raw, baseline_reservation_pinned=True)["state"], "unknown")
        self.assertNotIn("failurePhase", subject.classify(raw, baseline_reservation_pinned=True))


if __name__ == "__main__":
    unittest.main()

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fixture_storage_host as host
import native_fixture_storage as storage


def prevm_lock_admitted(ledger):
    """The creator pre-VM proof's exact ledger admission (storage_unenrolled)."""
    try:
        info = os.lstat(ledger)
        lock = os.open(ledger / "storage-plans.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        row = os.fstat(lock)
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022
                and ledger.resolve() == ledger and stat.S_ISREG(row.st_mode) and row.st_uid == os.geteuid()
                and row.st_nlink == 1 and stat.S_IMODE(row.st_mode) == 0o600)
    finally:
        os.close(lock)


class EnrollmentTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX storage-plan lock; the helper runs on Linux VM hosts")
    def test_unenrolled_host_refuses_then_enroll_admits_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(os.path.realpath(temporary)) / ".cache" / "vpn-control-fixture-storage"
            # The original 2026-10-26 archlinux state: no ledger at all.
            self.assertFalse(prevm_lock_admitted(ledger))
            self.assertFalse(ledger.is_dir())
            self.assertEqual(host.enroll(storage, str(ledger))["state"], "enrolled")
            self.assertTrue(prevm_lock_admitted(ledger))
            self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o700)
            self.assertFalse((ledger / "storage-plans.json").exists())
            self.assertEqual(storage.StoragePlans(ledger)._read(), {"schemaVersion": 1, "plans": {}})
            self.assertEqual(host.enroll(storage, str(ledger)),
                             {"state": "already-enrolled", "ledger": str(ledger), "plans": 0})

    @unittest.skipUnless(os.name == "posix", "POSIX storage-plan lock; the helper runs on Linux VM hosts")
    def test_unsafe_existing_ledger_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(os.path.realpath(temporary)) / "ledger"
            ledger.mkdir(mode=0o700)
            os.chmod(ledger, 0o777)
            with self.assertRaises(ValueError):
                host.enroll(storage, str(ledger))

    def test_coverage_and_register_refuse_unenrolled(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = str(Path(os.path.realpath(temporary)) / "absent")
            for call in (lambda: host.coverage(storage, ledger, {}), lambda: host.register(storage, ledger, {}, {})):
                with self.assertRaisesRegex(host.HostStorageError, "^fixture_storage_host_unenrolled$"):
                    call()

    def test_resolve_requires_exactly_one_actor(self):
        actors = {10: (1, "qemu -name vpn-control-0f559886-4ff5"), 11: (2, "qemu -name other")}
        self.assertEqual(host.resolve(actors, {"linux-0f559886-4ff5-4075-ad25-beb805173364": "linux"}),
                         {"linux-0f559886-4ff5-4075-ad25-beb805173364": {"platform": "linux", "pid": 10, "startTicks": 1}})
        for deployments in ({"linux-aaaaaaaa-0000": "linux"}, {"windows-0f559886-x": "linux"}):
            with self.assertRaises(host.HostStorageError):
                host.resolve(actors, deployments)
        with self.assertRaises(host.HostStorageError):
            host.resolve({**actors, 12: (3, "vpn-control-0f559886 again")}, {"linux-0f559886-4ff5": "linux"})

    def test_host_program_compiles_inline(self):
        program = host._program("register", {"linux-0f559886-4ff5": "linux"})
        compile(program, "fixture storage host program", "exec")
        self.assertLess(len(program), 60000)


@unittest.skipUnless(sys.platform.startswith("linux"), "real Linux /proc descriptor coverage")
class LinuxCoverageTest(unittest.TestCase):
    """The real lifecycle/creator coverage gate on the actual kernel: RED before
    registration (the attempt-2 capacity-phase block), GREEN after."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(os.path.realpath(self.temporary.name))
        self.ledger = root / "ledger"
        self.vm = root / "vc-r-test"
        self.vm.mkdir(mode=0o700)
        self.disk = self.vm / "disk.img"
        self.disk.write_bytes(b"\0" * 4096)
        os.chmod(self.disk, 0o600)
        self.actor = subprocess.Popen([sys.executable, "-c",
            "import sys,time;f=open(sys.argv[1],'r+b');print('ready',flush=True);time.sleep(120)", str(self.disk)],
            stdout=subprocess.PIPE)
        self.assertEqual(self.actor.stdout.readline().strip(), b"ready")
        self.start = host.birth(self.actor.pid)
        self.actors = {self.actor.pid: (self.start, "qemu -name vc-recovery-test")}
        host.enroll(storage, str(self.ledger))

    def tearDown(self):
        self.actor.kill()
        self.actor.wait()
        self.actor.stdout.close()
        self.temporary.cleanup()

    def _gate(self):
        from agent_tools import readiness_windows_lifecycle as lifecycle
        census = {"vms": [{"pid": self.actor.pid, "startTicks": self.start}]}
        lifecycle._storage_vm_coverage(storage.StoragePlans(self.ledger)._read(), census, host.birth)

    def test_unregistered_running_disk_blocks_then_register_covers(self):
        self.assertEqual(host.writable_disks(self.actor.pid), [str(self.disk)])
        with self.assertRaisesRegex(ValueError, "^instance_lifecycle_storage_coverage$"):
            self._gate()
        report = host.coverage(storage, str(self.ledger), self.actors)
        self.assertEqual(report["state"], "uncovered")
        self.assertEqual([row["path"] for row in report["uncovered"]], [str(self.disk)])
        fixtures = {"linux-test-fixture": {"platform": "linux", "pid": self.actor.pid, "startTicks": self.start}}
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 1024**4)):
            result = host.register(storage, str(self.ledger), fixtures, self.actors)
        self.assertEqual(result["linux-test-fixture"]["disks"], [{"path": str(self.disk), "capacityBytes": 4096}])
        plan = storage.StoragePlans(self.ledger)._read()["plans"]["linux-test-fixture"]
        self.assertEqual((plan["state"], plan["writerPid"], plan["directory"]), ("pending", self.actor.pid, str(self.vm)))
        self._gate()
        self.assertEqual(host.coverage(storage, str(self.ledger), self.actors), {"state": "covered", "uncovered": []})

    def test_changed_actor_identity_refuses_without_claim(self):
        fixtures = {"linux-test-fixture": {"platform": "linux", "pid": self.actor.pid, "startTicks": self.start + 1}}
        with self.assertRaisesRegex(host.HostStorageError, "^fixture_storage_host_actor_changed$"):
            host.register(storage, str(self.ledger), fixtures, {self.actor.pid: (self.start + 1, "")})
        self.assertEqual(storage.StoragePlans(self.ledger)._read()["plans"], {})

    def test_read_only_descriptor_is_not_a_writable_disk(self):
        reader = subprocess.Popen([sys.executable, "-c",
            "import sys,time;f=open(sys.argv[1],'rb');print('ready',flush=True);time.sleep(120)", str(self.disk)],
            stdout=subprocess.PIPE)
        try:
            self.assertEqual(reader.stdout.readline().strip(), b"ready")
            self.assertEqual(host.writable_disks(reader.pid), [])
        finally:
            reader.kill()
            reader.wait()
            reader.stdout.close()


if __name__ == "__main__":
    unittest.main()

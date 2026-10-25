import shutil
import tempfile
import os
import subprocess
import threading
import time
import hashlib
import json
import types
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

import native_fixture_storage as storage


class FixtureStorageTest(unittest.TestCase):
    def test_each_provider_has_stricter_bootstrap_budget_and_headroom(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 1024**4)):
            for platform in ("android", "linux", "windows", "macos"):
                with self.subTest(platform=platform):
                    start = storage.require_fixture_storage(platform, "start", temporary)
                    bootstrap = storage.require_fixture_storage(platform, "bootstrap", temporary)
                    self.assertGreater(bootstrap["requiredBytes"], start["requiredBytes"])
                    self.assertEqual(start["headroomBytes"], 2 * storage.GIB)

    def test_uncreated_destination_checks_its_existing_filesystem(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 8 * storage.GIB)) as usage:
            result = storage.require_fixture_storage("android", "start", Path(temporary) / "new" / "avd")
            self.assertEqual(result["requiredBytes"], 8 * storage.GIB)
            usage.assert_called_once_with(Path(temporary))

    def test_unknown_disk_visibility_refuses_before_write(self):
        with mock.patch.object(storage.shutil, "disk_usage", side_effect=OSError("private-data")):
            with self.assertRaisesRegex(storage.FixtureStorageError, "^fixture_disk_observation_unavailable$"):
                storage.require_fixture_storage("android", "start", Path.cwd())

    def test_sparse_raw_growth_and_caller_budget_can_only_increase_requirement(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 20 * storage.GIB)):
            disk = Path(temporary) / "disk.img"
            disk.write_bytes(b"inert")
            original_stat = Path.stat
            def observed_stat(path, *args, **kwargs):
                if path == disk:
                    return SimpleNamespace(st_size=32 * storage.GIB, st_blocks=0)
                return original_stat(path, *args, **kwargs)
            with mock.patch.object(Path, "stat", autospec=True, side_effect=observed_stat), \
                    self.assertRaisesRegex(storage.FixtureStorageError, "fixture_disk_capacity_insufficient"):
                storage.require_fixture_storage("macos", "start", temporary, sparse_raw_disks=(disk,))
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_disk_capacity_insufficient"):
                storage.require_fixture_storage("android", "start", temporary, writable_growth_bytes=24 * storage.GIB)

    def test_invalid_or_unclassified_inputs_fail_closed(self):
        for args in (("unknown", "start", 0), ("android", "reset", 0), ("android", "start", True),
                     ("android", "start", -1)):
            with self.subTest(args=args), self.assertRaises(storage.FixtureStorageError):
                storage.require_fixture_storage(args[0], args[1], Path.cwd(), writable_growth_bytes=args[2])

    def test_image_preparation_requires_explicit_positive_artifact_bound(self):
        capacity = 12_893_555_341
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, capacity + storage.HEADROOM_BYTES)):
            result = storage.require_fixture_storage("macos", "prepare-image", temporary,
                                                     writable_growth_bytes=capacity)
            self.assertEqual(result["requiredBytes"], capacity + storage.HEADROOM_BYTES)
            for bound in (0, -1, True):
                with self.subTest(bound=bound), self.assertRaises(storage.FixtureStorageError):
                    storage.require_fixture_storage("macos", "prepare-image", temporary, writable_growth_bytes=bound)
            with self.assertRaises(storage.FixtureStorageError):
                storage.require_fixture_storage("linux", "prepare-image", temporary, writable_growth_bytes=capacity)

    def test_exact_beforeimage_cannot_prepare_bounded_image_while_new_phase_can(self):
        directory=Path(__file__).resolve().parents[1]/"agent_tools/tests/fixtures/storage_prepare_image"
        source=(directory/"native_fixture_storage.before.source").read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(),json.loads((directory/"provenance.json").read_text())["sourceSha256"])
        before=types.ModuleType("before_storage");exec(compile(source,"<complete-original-storage>","exec"),before.__dict__)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                storage.shutil,"disk_usage",return_value=shutil._ntuple_diskusage(1024**4,0,16*storage.GIB)):
            with self.assertRaisesRegex(before.FixtureStorageError,"fixture_disk_policy_unknown"):
                before.require_fixture_storage("macos","prepare-image",temporary,writable_growth_bytes=12_893_555_341)
            self.assertEqual(storage.require_fixture_storage("macos","prepare-image",temporary,
                writable_growth_bytes=12_893_555_341)["requiredBytes"],12_893_555_341+storage.HEADROOM_BYTES)

    def test_two_sparse_disks_require_the_sum_of_remaining_growth(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 24 * storage.GIB)):
            disks = [Path(temporary) / name for name in ("linux.img", "macos.img")]
            for disk in disks:
                disk.write_bytes(b"inert")
            original_stat = Path.stat
            def observed_stat(path, *args, **kwargs):
                if path in disks:
                    return SimpleNamespace(st_size=16 * storage.GIB, st_blocks=0,
                                           st_dev=1, st_ino=disks.index(path)+1)
                return original_stat(path, *args, **kwargs)
            with mock.patch.object(Path, "stat", autospec=True, side_effect=observed_stat), \
                    self.assertRaisesRegex(storage.FixtureStorageError, "fixture_disk_capacity_insufficient"):
                storage.require_fixture_storage("macos", "start", temporary, sparse_raw_disks=disks)


@unittest.skipUnless(os.name == "posix", "shared provider storage plans require POSIX locks")
class StoragePlansTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.ledger = storage.StoragePlans(self.root / "ledger")

    def claim(self, name, capacity=8 * storage.GIB, pid=None):
        return self.ledger.reserve(name, "linux", "start", self.root,
                                   [{"path": str(self.root / (name + ".img")), "capacityBytes": capacity}],
                                   writer_pid=pid)

    def test_pending_files_keep_full_claim_and_other_provider_budget_adds(self):
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 20 * storage.GIB)):
            self.claim("linux-owned")
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_disk_capacity_insufficient"):
                self.ledger.reserve("mac-owned", "macos", "start", self.root,
                                    [{"path": str(self.root / "mac.img"), "capacityBytes": 16 * storage.GIB}])
            self.assertEqual(set(self.ledger._read()["plans"]), {"linux-owned"})

    def test_concurrent_callers_share_capacity_lock(self):
        barrier = threading.Barrier(2)
        outcomes = []
        def call(name):
            barrier.wait()
            try:
                self.claim(name)
                outcomes.append("admitted")
            except storage.FixtureStorageError:
                outcomes.append("blocked")
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 12 * storage.GIB)):
            threads = [threading.Thread(target=call, args=(name,)) for name in ("first", "second")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertEqual(sorted(outcomes), ["admitted", "blocked"])

    def test_unknown_or_running_writer_cannot_settle_or_retire(self):
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 64 * storage.GIB)):
            self.claim("unknown")
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_storage_writer_unresolved"):
                self.ledger.settle("unknown", retire=True)
            self.claim("running", pid=os.getpid())
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_storage_writer_not_absent"):
                self.ledger.settle("running", retire=True)

    def test_retirement_requires_original_actor_absence_and_disk_removal(self):
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        child.wait(timeout=5)
        path = self.root / "closed.img"
        path.write_bytes(b"owned")
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 64 * storage.GIB)):
            self.claim("closed", pid=child.pid)
            self.ledger.settle("closed")
            self.assertEqual(self.ledger._read()["plans"]["closed"]["state"], "retained")
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_storage_disk_closure_unproven"):
                self.ledger.settle("closed", retire=True)
            path.unlink()
            self.ledger.settle("closed", retire=True)
            self.assertEqual(self.ledger._read()["plans"]["closed"]["state"], "retired")

    @unittest.skipUnless(hasattr(os, "waitid") and hasattr(os, "WNOWAIT"), "kernel terminal-child observation required")
    def test_terminal_unreaped_original_child_is_not_a_live_disk_writer(self):
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        try:
            end = time.monotonic() + 5
            while time.monotonic() < end:
                terminal = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if terminal is not None:
                    break
                time.sleep(.01)
            self.assertIsNotNone(terminal)
            path = self.root / "terminal.img"
            path.write_bytes(b"owned")
            with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 64 * storage.GIB)):
                self.claim("terminal", pid=child.pid)
                self.ledger.settle("terminal")
                self.assertEqual(self.ledger._read()["plans"]["terminal"]["state"], "retained")
                # Admission only observes the kernel receipt; the original Popen
                # owner still collects its child exactly once.
                self.assertIsNotNone(os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
        finally:
            child.wait(timeout=5)

    def test_tart_shared_clone_retains_full_virtual_writable_budget(self):
        home = self.root / "home"
        vm = home / ".tart/vms/task-owned"; vm.mkdir(parents=True)
        disk = vm / "disk.img"; disk.write_bytes(b"x" * (8 * 1024**2)); disk.chmod(0o600)
        # APFS st_blocks includes cloned base extents. Their existing allocation
        # cannot be subtracted from future overwrite/COW space without proof.
        available = 22 * storage.GIB - 4 * 1024**2
        with mock.patch.object(Path, "home", return_value=home), mock.patch.object(
                storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, available)):
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_disk_capacity_insufficient"):
                self.ledger.reserve("tart-shared", "linux", "start", vm,
                    [{"path": str(disk), "capacityBytes": 20 * storage.GIB}])

    def test_bootstrap_staging_adds_download_or_cache_peak_before_any_writer(self):
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 48 * storage.GIB)):
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_disk_capacity_insufficient"):
                self.ledger.reserve("mac-cold", "macos", "bootstrap", self.root,
                    [{"path": str(self.root / "mac.img"), "capacityBytes": 32 * storage.GIB}],
                    staging_growth_bytes=17 * storage.GIB)
            self.assertFalse((self.ledger.directory / "storage-plans.json").exists())

    def test_changed_original_paths_or_capacity_refuse(self):
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 64 * storage.GIB)):
            self.claim("fixed")
            with self.assertRaisesRegex(storage.FixtureStorageError, "fixture_storage_original_plan_conflict"):
                self.claim("fixed", capacity=16 * storage.GIB)

    def test_image_claim_adds_exact_artifact_to_all_pending_and_retained_claims(self):
        capacity = 12_893_555_341
        directory = self.root / "apple-asset"; directory.mkdir(mode=0o700)
        disk = {"path": str(directory / "Restore.ipsw"), "capacityBytes": capacity}
        with mock.patch.object(storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 100 * storage.GIB)):
            self.claim("android-unknown", capacity=6 * storage.GIB)
            self.ledger.reserve("retained", "windows", "start", self.root,
                                [{"path":str(self.root / "retained.img"), "capacityBytes":10 * storage.GIB}])
            state=self.ledger._read();state["plans"]["retained"]["state"]="retained";self.ledger._save(state)
            result=self.ledger.reserve("apple-image", "macos", "prepare-image", directory, [disk])
            self.assertEqual(result["candidateGrowthBytes"], capacity)
            self.assertEqual(result["otherOwnedGrowthBytes"], 16 * storage.GIB)
            self.assertEqual(result["requiredBytes"], capacity + 18 * storage.GIB)
            plan=self.ledger._read()["plans"]["apple-image"]
            self.assertEqual((plan["workingBytes"],plan["stagingBytes"],plan["writerPid"]),(0,0,None))
            original=self.ledger._read()
            with mock.patch.object(storage.shutil,"disk_usage",return_value=shutil._ntuple_diskusage(1024**4,0,result["requiredBytes"]-1)):
                with self.assertRaisesRegex(storage.FixtureStorageError,"fixture_disk_capacity_insufficient"):
                    self.ledger.check("macos","prepare-image",directory,current_fixture_id="apple-image")
            self.assertEqual(self.ledger._read(),original)

    def test_image_check_without_current_claim_requires_positive_bound(self):
        with mock.patch.object(storage.shutil,"disk_usage",return_value=shutil._ntuple_diskusage(1024**4,0,64*storage.GIB)):
            with self.assertRaisesRegex(storage.FixtureStorageError,"fixture_disk_requirement_invalid"):
                self.ledger.check("macos","prepare-image",self.root)
            result=self.ledger.check("macos","prepare-image",self.root,minimum_growth_bytes=12345)
            self.assertEqual(result["requiredBytes"],12345+storage.HEADROOM_BYTES)
            self.assertFalse((self.ledger.directory/"storage-plans.json").exists())

    def test_image_phase_rejects_vm_disks_staging_multiple_or_nonprivate_destination(self):
        folder=self.root/"image";folder.mkdir(mode=0o700)
        disk={"path":str(folder/"Restore.ipsw"),"capacityBytes":12345}
        for disks,staging in (([{**disk,"path":str(folder/"disk.img")}],0),([disk,disk],0),([disk],1),([{**disk,"capacityBytes":0}],0),([{**disk,"path":str(self.root/"Restore.ipsw")}],0)):
            with self.subTest(disks=disks,staging=staging), self.assertRaisesRegex(storage.FixtureStorageError,"fixture_storage_image_plan_invalid"):
                self.ledger.reserve("image","macos","prepare-image",folder,disks,staging_growth_bytes=staging)
        folder.chmod(0o755)
        with self.assertRaisesRegex(storage.FixtureStorageError,"fixture_storage_image_directory_unsafe"):
            self.ledger.reserve("image","macos","prepare-image",folder,[disk])
        self.assertFalse((self.ledger.directory/"storage-plans.json").exists())


if __name__ == "__main__":
    unittest.main()

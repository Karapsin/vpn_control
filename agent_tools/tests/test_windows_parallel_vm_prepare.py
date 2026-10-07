"""Actual TempFS/shared copy/QEMU lock tests; never Windows acceptance."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
import uuid
from unittest.mock import patch

from agent_tools import windows_parallel_vm_prepare as prepare
from agent_tools import windows_parallel_vm_source_inventory as inventory


@unittest.skipUnless(os.name == "posix", "native FD and fsync guards require POSIX")
class LockEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def harmless(self, code):
        real_popen = subprocess.Popen
        with patch.object(prepare.subprocess, "Popen", side_effect=lambda *a, **kw:
                          real_popen([sys.executable, "-c", code], **kw)):
            lock = prepare.ReadLock("unused-qemu-io", self.root / "source.qcow2", self.root)
        def cleanup():
            if lock.child.poll() is None:
                lock.child.kill()  # Positively owned harmless test child only.
            lock.child.wait(timeout=2)
            if lock.raw_fd is not None:
                lock.dispose()
        self.addCleanup(cleanup)
        return lock

    def test_original_unknown_child_retains_fsynced_prefix_and_handle(self):
        lock = self.harmless("import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(2)")
        with self.assertRaises(prepare.LockUnknown) as caught:
            lock.observe(.1)
        self.assertIs(caught.exception.lock, lock)
        self.assertEqual(lock.raw_path.read_bytes(), b"PUBLIC_PREFIX")
        self.assertFalse(lock.ready)
        self.assertFalse(lock.eof)
        self.assertIsNone(lock.child.poll())

    def test_unsafe_raw_name_still_exposes_original_child_and_raw_fd(self):
        lock = self.harmless("import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(2)")
        original = prepare.ReadLock.append
        def replace(receiver, raw):
            original(receiver, raw)
            receiver.raw_path.rename(self.root / "held-original.private")
            receiver.raw_path.write_bytes(b"foreign")
            receiver.flush()
        with patch.object(prepare.ReadLock, "append", replace):
            with self.assertRaises(prepare.LockUnknown) as caught:
                lock.observe(.1)
        self.assertIs(caught.exception.lock, lock)
        self.assertEqual((self.root / "held-original.private").read_bytes(), b"PUBLIC_PREFIX")
        self.assertIsNone(lock.child.poll())
        self.assertFalse(lock.eof)

    def test_actual_overflow_bounds_retained_original_prefix(self):
        lock = self.harmless("import os,time;os.write(1,b'X'*100000);time.sleep(2)")
        with self.assertRaises(prepare.LockUnknown):
            lock.observe(1)
        self.assertEqual(len(lock.raw), prepare.RAW_LIMIT + 1)
        self.assertEqual(lock.raw_path.stat().st_size, prepare.RAW_LIMIT + 1)
        self.assertFalse(lock.ready)


@unittest.skipUnless(os.name == "posix" and shutil.which("qemu-img") and shutil.which("qemu-io"),
                     "actual harmless QEMU utilities required; no native VM substitute")
class QemuPreparationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source.qcow2"
        self.qemu_img, self.qemu_io = shutil.which("qemu-img"), shutil.which("qemu-io")
        subprocess.run([self.qemu_img, "create", "-f", "qcow2", str(self.source), "96G"],
                       check=True, stdout=subprocess.DEVNULL)
        self.source.chmod(0o600)
        self.proc = self.root / "proc"
        (self.proc / "net").mkdir(parents=True)
        for name in ("tcp", "tcp6", "unix"):
            (self.proc / "net" / name).write_text("header\n")
        self.scope = prepare.Scope(self.source, self.root, self.root / "template",
                                   (self.root / "secondary", self.root / "tertiary"), self.proc,
                                   self.qemu_img, self.qemu_io)
        self.pin = {"generation": inventory.generation(self.source.lstat()),
                    "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
                    "parents": [{"path": str(p), "generation": g}
                                for p, g in inventory.parent_pins(self.source, self.root)]}
        self.source_bytes = self.source.read_bytes()
        self.correlation = str(uuid.uuid4())

    def native_process_projection(self, lock_class=prepare.ReadLock):
        # macOS lacks Linux /proc. Only the host process-table boundary is
        # projected; real qemu-io source opens/write exclusion and the actual
        # parser/copy/hash/source guards/census inode reads execute unchanged.
        original_init, original_close = lock_class.__init__, lock_class.close
        def start(lock, binary, source, evidence):
            original_init(lock, binary, source, evidence)
            directory = self.proc / str(lock.child.pid)
            (directory / "fd").mkdir(parents=True)
            (directory / "stat").write_text(str(lock.child.pid) + " (qemu-io) " +
                " ".join(["S"] + ["0"] * 18 + ["123"]))
            (directory / "comm").write_text("qemu-io")
            (directory / "cmdline").write_bytes(os.fsencode(binary) + b"\0")
            (directory / "fd" / "9").symlink_to(source)
        def close(lock):
            original_close(lock)
            shutil.rmtree(self.proc / str(lock.child.pid))
        return patch.object(lock_class, "__init__", start), patch.object(lock_class, "close", close)

    def run_core(self):
        start, close = self.native_process_projection()
        with start, close:
            return prepare.prepare_core(self.scope, self.pin, self.correlation, disk_reserve=0)

    def test_actual_qemu_lock_excludes_writable_open_on_own_scratch(self):
        evidence = self.root / "scratch-evidence"
        evidence.mkdir(mode=0o700)
        self.assertTrue(prepare.prove_write_exclusion(self.scope, evidence))
        raw = (evidence / "locking-write-open.stdout.private").read_bytes()
        self.assertIn(b'Failed to get "write" lock', raw)
        self.assertFalse(json.loads((evidence / "write-exclusion.json").read_bytes())["sourceWritableOpenAttempted"])
        self.assertEqual(self.source.read_bytes(), self.source_bytes)

    def test_actual_whole_core_uses_shared_copy_and_creates_independent_overlays(self):
        real_copy = prepare.baseline.QemuProvider.copy
        with patch.object(prepare.baseline.QemuProvider, "copy", autospec=True, side_effect=real_copy) as copy:
            result = self.run_core()
        self.assertEqual(copy.call_count, 1)
        template = self.scope.template_root / "template.qcow2"
        self.assertEqual(template.read_bytes(), self.source_bytes)
        self.assertEqual(result["templateSha256"], self.pin["sha256"])
        self.assertEqual(result["templateGeneration"], inventory.generation(template.lstat()))
        self.assertEqual(template.lstat().st_mode & 0o777, 0o440)
        self.assertEqual(self.scope.template_root.lstat().st_mode & 0o777, 0o750)
        self.assertTrue(result["ordinaryQemuReadAccessConfigured"])
        self.assertFalse(result["nativeGuestStarted"])
        self.assertFalse(result["productAcceptance"])
        self.assertEqual(len(result["overlays"]), 2)
        for guest in self.scope.guests:
            info = json.loads(subprocess.check_output([self.qemu_img, "info", "--output=json", str(guest / "disk.qcow2")]))
            self.assertEqual(info["full-backing-filename"], str(template))
        self.assertEqual(inventory.generation(self.source.lstat()), self.pin["generation"])
        with self.assertRaisesRegex(ValueError, "template-exists"):
            self.run_core()

    def test_generated_exact_program_primitives_execute_whole_local_copy(self):
        plan = {"sourcePin": self.pin, "templateRoot": str(prepare.TEMPLATE_ROOT),
                "guestRoots": list(inventory.DESTINATIONS)}
        program = prepare.remote_program(plan, self.correlation)
        self.assertIn("need(os.geteuid()==0,'privilege-required')", program)
        self.assertIn("/home/kardinal/vpn-control-windows-native-20260907/task.qcow2", program)
        self.assertNotIn("qemu-system", program.split("class ReadLock:", 1)[1])
        module = types.ModuleType("windows_parallel_copy_generated_proof")
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        # Project only fixed native entry scope/privilege/process-table. The
        # generated actual definitions and shared methods execute unchanged.
        exec(program.split("\nos.environ['PATH']=", 1)[0], module.__dict__)
        scope = module.Scope(**vars(self.scope))
        start, close = self.native_process_projection(module.ReadLock)
        with start, close:
            value = module.prepare_core(scope, self.pin, self.correlation, disk_reserve=0)
        self.assertEqual(value["state"], "prepared")
        self.assertEqual(value["templateSha256"], self.pin["sha256"])
        self.assertEqual((self.scope.template_root / "template.qcow2").read_bytes(), self.source_bytes)
        self.assertFalse(value["nativeGuestStarted"])
        self.assertFalse(value["productAcceptance"])

    def test_source_drift_and_disk_budget_refuse_before_any_namespace(self):
        self.source.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "source-generation"):
            self.run_core()
        self.assertFalse(self.scope.template_root.exists())
        self.source.write_bytes(self.source_bytes)
        self.pin["generation"] = inventory.generation(self.source.lstat())
        space = os.statvfs(self.root)
        with self.assertRaisesRegex(ValueError, "copy-disk-budget"):
            prepare.prepare_core(self.scope, self.pin, self.correlation,
                                 disk_reserve=space.f_bavail * space.f_frsize)
        self.assertFalse(self.scope.template_root.exists())

    def test_whole_core_refuses_earlier_overlay_mutation_during_second_info(self):
        real_run = prepare.subprocess.run
        first, second = (p / "disk.qcow2" for p in self.scope.guests)
        def mutate(argv, *args, **kwargs):
            result = real_run(argv, *args, **kwargs)
            if len(argv) > 1 and argv[1] == "info" and str(second) in argv:
                first.chmod(0o666)
            return result
        with patch.object(prepare.subprocess, "run", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "overlay-closing-generation"):
                self.run_core()
        self.assertEqual(first.lstat().st_mode & 0o777, 0o666)
        evidence = self.scope.template_root / "evidence"
        self.assertFalse((evidence / "result.json").exists())
        self.assertEqual(json.loads((evidence / "unknown.json").read_bytes())["state"], "unknown")

    def test_actual_partial_shared_copy_retains_unknown_and_forbids_replay(self):
        def partial(provider, source, destination):
            destination.write_bytes(b"PUBLIC_PARTIAL_DISK")
            raise OSError("measured harmless partial copy")
        with patch.object(prepare.baseline.QemuProvider, "copy", partial):
            with self.assertRaises(OSError):
                self.run_core()
        evidence = self.scope.template_root / "evidence"
        unknown = json.loads((evidence / "unknown.json").read_bytes())
        self.assertEqual(unknown["state"], "unknown")
        self.assertEqual(unknown["phase"], "copy")
        self.assertFalse((evidence / "result.json").exists())
        self.assertEqual((self.scope.template_root / "template.qcow2").read_bytes(), b"PUBLIC_PARTIAL_DISK")
        self.assertFalse(any(p.exists() for p in self.scope.guests))
        self.assertTrue((evidence / "source-lock" / "read-lock.stdout.private").is_file())
        with self.assertRaisesRegex(ValueError, "template-exists"):
            self.run_core()

    def test_actual_namespace_swap_keeps_unknown_in_original_held_journal(self):
        real_copy = prepare.baseline.QemuProvider.copy
        displaced = self.root / "displaced-template"
        def replace(provider, source, destination):
            real_copy(provider, source, destination)
            self.scope.template_root.rename(displaced)
            self.scope.template_root.mkdir(mode=0o700)
            (self.scope.template_root / "evidence").mkdir(mode=0o700)
        with patch.object(prepare.baseline.QemuProvider, "copy", replace):
            with self.assertRaises(prepare.LockUnknown) as caught:
                self.run_core()
        lock = caught.exception.lock
        lock.child.wait(timeout=2)  # Original fixed quit exits naturally.
        lock.dispose()
        unknown = json.loads((displaced / "evidence" / "unknown.json").read_bytes())
        self.assertEqual(unknown["reason"], "preparation-namespace-changed")
        self.assertEqual(unknown["phase"], "copy")
        self.assertFalse((self.scope.template_root / "evidence" / "unknown.json").exists())
        self.assertFalse((displaced / "evidence" / "result.json").exists())
        self.assertEqual((displaced / "template.qcow2").read_bytes(), self.source_bytes)
        self.assertFalse(any(p.exists() for p in self.scope.guests))


if __name__ == "__main__":
    unittest.main()

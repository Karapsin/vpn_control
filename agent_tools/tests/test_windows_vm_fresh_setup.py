"""Admission and replay tests for the isolated Windows setup VM."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zlib
from threading import Barrier
import unittest
from unittest import mock

from agent_tools import windows_vm_fresh_setup as setup


CORR = "123e4567-e89b-12d3-a456-426614174000"
IDENTITY = {"reservationId": "env-test", "token": "test-token", "hostAlias": "archlinux",
            "environment": setup.ENVIRONMENT, "operator": setup.OPERATOR}
RESERVATION = {"hostAlias": "archlinux", "environment": setup.ENVIRONMENT, "operator": setup.OPERATOR,
               "requestedMemoryBytes": setup.MEMORY_MIB * 1024 * 1024, "allocationState": "pending",
               "reservationIdentity": IDENTITY}


def program(**changes):
    values = {"ROOT": setup.ROOT, "GUEST": setup.GUEST, "CORR": CORR, "MODE": "preflight",
              "WIN": setup.WINDOWS_ISO, "WIN_HASH": setup.WINDOWS_SHA256, "WIN_SIZE": setup.WINDOWS_SIZE,
              "DRV": setup.DRIVER_ISO, "DRV_HASH": setup.DRIVER_SHA256, "DRV_SIZE": setup.DRIVER_SIZE,
              "PORT": setup.VNC_PORT, "MEM": setup.MEMORY_MIB, "HEADROOM": setup.HEADROOM_KIB,
              "MIN_DISK": setup.MIN_DISK_KIB}
    values.update(changes)
    result = setup._REMOTE
    for key, value in values.items():
        result = result.replace("__" + key + "__", repr(value))
    return result


class WindowsVmFreshSetupTest(unittest.TestCase):
    def test_remote_program_compiles_and_binds_fixed_sources(self):
        text = program(MODE="start")
        compile(text, "<windows-vm-fresh-setup>", "exec")
        self.assertIn(setup.WINDOWS_SHA256, text)
        self.assertIn(setup.DRIVER_SHA256, text)
        self.assertIn("os.mkdir(GUEST,0o700)", text)
        self.assertIn("'-vnc','127.0.0.1:'", text)
        self.assertNotIn("seed.iso", text)
        self.assertNotIn("autounattend", text.lower())

    def test_start_journals_before_remote_submission_and_never_replays(self):
        with tempfile.TemporaryDirectory() as root:
            with (mock.patch.object(setup, "_remote", return_value={"state": "running-observed", "reason": None}) as remote,
                  mock.patch.object(setup.native_environment, "reserve_environment",
                                    return_value={"state": "reserved", "identity": IDENTITY,
                                                  "reservation": {"allocationState": "pending"}}) as reserve):
                result = setup.start(root, host="archlinux", correlation_id=CORR, reservation_request=RESERVATION)
                self.assertEqual("running-observed", result["state"])
                self.assertFalse(result["replayAllowed"])
                self.assertTrue(setup._intent(root, create=False).exists())
                with self.assertRaisesRegex(ValueError, "intent exists"):
                    setup.start(root, host="archlinux", correlation_id=CORR, reservation_request=RESERVATION)
                remote.assert_called_once()
                reserve.assert_called_once()

    def test_unknown_submission_keeps_intent_and_exact_status_only(self):
        with tempfile.TemporaryDirectory() as root:
            with (mock.patch.object(setup, "_remote", side_effect=TimeoutError),
                  mock.patch.object(setup.native_environment, "reserve_environment",
                                    return_value={"state": "reserved", "identity": IDENTITY,
                                                  "reservation": {"allocationState": "pending"}})):
                result = setup.start(root, host="archlinux", correlation_id=CORR, reservation_request=RESERVATION)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with mock.patch.object(setup, "_remote", return_value={"state": "unknown", "reason": None}):
                self.assertEqual("unknown", setup.status(root, host="archlinux", correlation_id=CORR)["state"])

    def test_distinct_correlations_cannot_race_for_start(self):
        other = "123e4567-e89b-12d3-a456-426614174001"
        with tempfile.TemporaryDirectory() as root:
            path = setup._intent(root, create=True)
            barrier = Barrier(2)

            def claim(correlation):
                barrier.wait(timeout=5)
                try:
                    setup._save(path, correlation)
                    return "claimed"
                except FileExistsError:
                    return "rejected"

            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertCountEqual(["claimed", "rejected"], list(pool.map(claim, (CORR, other))))

    def test_existing_guest_root_blocks_before_native_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            guest = Path(root) / "guest"
            guest.mkdir()
            result = subprocess.run([sys.executable, "-c", program(ROOT=root, GUEST=str(guest))],
                                    check=True, capture_output=True, text=True, timeout=5)
            value = json.loads(result.stdout)
            self.assertEqual("blocked", value["state"])
            self.assertEqual("guest-root-exists", value["reason"])
            self.assertEqual([], list(guest.iterdir()))

    def test_unjournaled_guest_is_unknown_and_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            guest = Path(root) / "guest"
            guest.mkdir(mode=0o700)
            os.chmod(guest, 0o700)
            result = subprocess.run([sys.executable, "-c", program(ROOT=root, GUEST=str(guest), MODE="status")],
                                    check=True, capture_output=True, text=True, timeout=5)
            self.assertEqual("unknown", json.loads(result.stdout)["state"])
            self.assertTrue(guest.exists())

    def test_status_finds_single_exact_qemu_after_crash_before_started_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            guest = Path(root) / "guest"
            guest.mkdir(mode=0o700)
            os.chmod(guest, 0o700)
            (guest / "intent.json").write_text(json.dumps({"correlationId": CORR,
                "windowsSha256": setup.WINDOWS_SHA256, "driverSha256": setup.DRIVER_SHA256}))
            proc = Path(root) / "proc"
            process = proc / "123"
            process.mkdir(parents=True)
            (process / "stat").write_text("123 (qemu-system-x86_64) S " + "0 " * 18 + "777")
            (process / "comm").write_text("qemu-system-x8\n")
            binary = Path(root) / "qemu-system-x86_64"
            binary.write_bytes(b"binary")
            (process / "exe").symlink_to(binary)
            disk = guest / "disk.qcow2"
            disk.write_bytes(b"disk")
            (process / "fd").mkdir()
            (process / "fd" / "3").symlink_to(disk)
            (process / "fd" / "4").symlink_to("socket:[111]")
            (proc / "net").mkdir()
            (proc / "net" / "unix").write_text("header\n000: 000 000 000 000 000 111 " + str(guest / "qmp.sock") + "\n")
            (process / "cmdline").write_bytes(b"qemu-system-x86_64\x00-drive\x00file=" +
                str(disk).encode() + b",if=virtio,format=qcow2\x00-qmp\x00unix:" +
                str(guest / "qmp.sock").encode() + b",server=on,wait=off\x00")
            script = program(ROOT=root, GUEST=str(guest), MODE="status").replace("/proc", str(proc))
            result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual("running-unrecorded-observed", json.loads(result.stdout)["state"])
            self.assertFalse((guest / "started.json").exists())
            (guest / "started.json").write_text(json.dumps({"pid": 123, "startTicks": 777}))
            recorded = subprocess.run([sys.executable, "-c", script], capture_output=True,
                                      text=True, timeout=5, check=True)
            self.assertEqual("running-observed", json.loads(recorded.stdout)["state"])
            changed_generation = script.replace("after=ticks(pid)", "after=before+1")
            changed = subprocess.run([sys.executable, "-c", changed_generation], capture_output=True,
                                     text=True, timeout=5, check=True)
            self.assertEqual("unknown", json.loads(changed.stdout)["state"])
            other = proc / "124"
            other.mkdir()
            (other / "stat").write_text("124 (qemu-system-x86_64) S " + "0 " * 18 + "778")
            (other / "comm").write_text("qemu-system-x8\n")
            unreadable = subprocess.run([sys.executable, "-c", script], capture_output=True,
                                        text=True, timeout=5, check=True)
            self.assertEqual("unknown", json.loads(unreadable.stdout)["state"])

    def test_other_host_and_invalid_correlation_rejected_before_remote(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(setup, "_remote") as remote:
            with self.assertRaises(ValueError):
                setup.preflight(root, host="fedora", correlation_id=CORR)
            with self.assertRaises(ValueError):
                setup.start(root, host="archlinux", correlation_id="wrong", reservation_request=RESERVATION)
            remote.assert_not_called()

    @unittest.skipUnless(shutil.which("qemu-img"), "qemu-img unavailable")
    def test_inert_qemu_img_probe_keeps_claimed_inode_and_publishes_once(self):
        with tempfile.TemporaryDirectory() as root:
            task = Path(root) / "task"
            task.mkdir(mode=0o700)
            os.chmod(task, 0o700)
            script = (setup._PROBE_REMOTE.replace("__ROOT__", repr(str(task)))
                      .replace("__CORR__", repr(CORR)).replace("__MODE__", repr("start")))
            first = subprocess.run([sys.executable, "-c", script], capture_output=True,
                                   text=True, timeout=10, check=True)
            self.assertEqual("verified", json.loads(first.stdout)["state"])
            self.assertTrue((task / "qemu-img-create-probe" / "disk.qcow2").is_file())
            self.assertFalse((task / "qemu-img-create-probe" / "disk.create.qcow2").exists())
            second = subprocess.run([sys.executable, "-c", script], capture_output=True,
                                    text=True, timeout=10, check=True)
            self.assertEqual("unknown", json.loads(second.stdout)["state"])

    def test_screen_capture_is_journaled_and_cannot_be_replayed(self):
        frame = b"P6\n320 240\n255\n" + bytes(320 * 240 * 3)
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(setup, "_screen_remote", return_value={"state": "observed", "frame": frame,
                    "sha256": hashlib.sha256(frame).hexdigest(), "width": 320, "height": 240}) as remote:
                result = setup.screen_start(root, host="archlinux", correlation_id=CORR)
                self.assertEqual("observed", result["state"])
                self.assertEqual(frame, Path(result["framePath"]).read_bytes())
                with self.assertRaises(FileExistsError):
                    setup.screen_start(root, host="archlinux", correlation_id=CORR)
                self.assertEqual("observed", setup.screen_status(root, host="archlinux", correlation_id=CORR)["state"])
                self.assertEqual(2, remote.call_count)

    def test_screen_status_rejects_changed_local_frame(self):
        frame = b"P6\n320 240\n255\n" + bytes(320 * 240 * 3)
        with tempfile.TemporaryDirectory() as root:
            path = setup._screen_intent(root, create=True)
            setup._save(path, CORR)
            local_frame = path.parent / ("frame-" + CORR + ".ppm")
            local_frame.write_bytes(b"wrong")
            os.chmod(local_frame, 0o600)
            with mock.patch.object(setup, "_screen_remote", return_value={"state": "observed", "frame": frame,
                    "sha256": hashlib.sha256(frame).hexdigest(), "width": 320, "height": 240}):
                with self.assertRaisesRegex(ValueError, "local frame changed"):
                    setup.screen_status(root, host="archlinux", correlation_id=CORR)

    def test_screen_transport_rejects_digest_mismatch(self):
        frame = b"P6\n320 240\n255\n" + bytes(320 * 240 * 3)
        response = {"schemaVersion": 1, "correlationId": CORR, "state": "observed", "nativeActionAllowed": False,
                    "width": 320, "height": 240, "frameSizeBytes": len(frame), "frameSha256": "0" * 64,
                    "frameBase64": base64.b64encode(zlib.compress(frame)).decode()}
        with (mock.patch.object(setup.ssh_transport, "load_config", return_value=mock.Mock(hosts={"archlinux": mock.Mock()})),
              mock.patch.object(setup.ssh_transport, "connection_host", return_value=mock.Mock(password=None)),
              mock.patch.object(setup.ssh_transport, "build_ssh_argv", return_value=["ssh"]),
              mock.patch.object(setup.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=json.dumps(response).encode()))):
            with self.assertRaisesRegex(ValueError, "digest changed"):
                setup._screen_remote(".", "archlinux", CORR, "screen-status", 60)

    def test_screen_command_refuses_unowned_vm_before_qmp_or_output(self):
        with tempfile.TemporaryDirectory() as root:
            task = Path(root) / "task"
            guest = task / "guest"
            guest.mkdir(parents=True, mode=0o700)
            os.chmod(guest, 0o700)
            (guest / "intent.json").write_text(json.dumps({"correlationId": CORR,
                "windowsSha256": setup.WINDOWS_SHA256, "driverSha256": setup.DRIVER_SHA256}))
            script = program(ROOT=str(task), GUEST=str(guest), MODE="screen-start")
            result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                                    text=True, timeout=5, check=True)
            self.assertEqual("unknown", json.loads(result.stdout)["state"])
            self.assertEqual([], list(guest.glob("screen-*.ppm")))

    def test_start_requires_exact_pending_capacity_reservation(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(setup, "_remote") as remote:
            with self.assertRaisesRegex(ValueError, "pending host reservation"):
                setup.start(root, host="archlinux", correlation_id=CORR,
                            reservation_request={**RESERVATION, "requestedMemoryBytes": 1})
            self.assertFalse((Path(root) / ".rag_index").exists())
            remote.assert_not_called()

    def test_journal_rejects_symlinked_or_shared_rag_ancestor(self):
        with tempfile.TemporaryDirectory() as root:
            rag = Path(root) / ".rag_index"
            target = Path(root) / "target"
            target.mkdir(mode=0o700)
            rag.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "journal is unsafe"):
                setup._intent(root, create=True)
            rag.unlink()
            rag.mkdir(mode=0o755)
            os.chmod(rag, 0o755)
            with self.assertRaisesRegex(ValueError, "journal is unsafe"):
                setup._intent(root, create=True)

    def test_inserted_firmware_vars_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            task = Path(root) / "task"
            task.mkdir(mode=0o700)
            vars_source = Path(root) / "vendor-vars.fd"
            vars_source.write_bytes(b"vendor")
            script = program(ROOT=str(task), GUEST=str(task / "guest"), MODE="start")
            script = script.replace("firmware,available,free=availability()", "firmware,available,free=(('code'," + repr(str(vars_source)) + "),0,0)")
            script = script.replace("os.mkdir(GUEST,0o700);private_dir(GUEST)",
                                    "os.mkdir(GUEST,0o700);private_dir(GUEST);open(GUEST+'/uefi-vars.fd','wb').write(b'sentinel')")
            result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual("unknown", json.loads(result.stdout)["state"])
            self.assertEqual(b"sentinel", (task / "guest" / "uefi-vars.fd").read_bytes())

    def test_inserted_disk_temp_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            task = Path(root) / "task"
            task.mkdir(mode=0o700)
            vars_source = Path(root) / "vendor-vars.fd"
            vars_source.write_bytes(b"vendor")
            script = program(ROOT=str(task), GUEST=str(task / "guest"), MODE="start")
            script = script.replace("firmware,available,free=availability()", "firmware,available,free=(('code'," + repr(str(vars_source)) + "),0,0)")
            script = script.replace("temp=GUEST+'/disk.create.qcow2'", "open(GUEST+'/disk.create.qcow2','wb').write(b'sentinel');temp=GUEST+'/disk.create.qcow2'")
            result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual("unknown", json.loads(result.stdout)["state"])
            self.assertEqual(b"sentinel", (task / "guest" / "disk.create.qcow2").read_bytes())


if __name__ == "__main__":
    unittest.main()

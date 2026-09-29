"""Causal guards for the one-shot disposable Windows optical boot action."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import textwrap
import types
import unittest
from unittest import mock

from agent_tools import windows_vm_optical_boot as boot


CORR = "123e4567-e89b-12d3-a456-426614174099"


class WindowsVmOpticalBootTest(unittest.TestCase):
    def test_program_is_one_reset_one_qmp_space_and_no_ocr(self):
        program = boot._program(CORR, "start")
        compile(program, "<optical-boot>", "exec")
        self.assertEqual(1, program.count("command('system_reset')"))
        self.assertEqual(1, program.count("command('send-key'"))
        self.assertIn("'hold-time':HOLD_MS", program)
        self.assertIn("'data':'spc'", program)
        self.assertIn("DELAY_MS=3000", program)
        self.assertIn("HOLD_MS=300", program)
        self.assertNotIn("tesseract", program.lower())
        self.assertNotIn("ocr", program.lower())
        self.assertNotIn("human-monitor-command", program)
        self.assertNotIn("sendkey", program)
        self.assertIn("if MODE=='status' and os.path.lexists(INTENT)", program)
        self.assertIn("elif MODE=='status':disk=None", program)

    def test_fixed_guest_owner_binds_disk_iso_qmp_and_generation(self):
        program = boot._program(CORR, "start")
        self.assertIn("ticks(pid)!=generation", program)
        self.assertIn("optical not in argv", program)
        self.assertIn("diskarg not in argv", program)
        self.assertIn("qmp not in argv", program)
        self.assertIn("not diskheld or not isoheld", program)
        self.assertIn("not qmp_socket_owned(lines[1:],fds)", program)
        self.assertIn("(owner['isoDevice'],owner['isoInode'])!=(media['device'],media['inode'])", program)
        self.assertIn("memory!=[b'6144']", program)

    def test_actual_qemu_memory_arg_rejects_foreign_or_duplicate_allocation(self):
        program = boot._program(CORR, "start")
        expression = program.split(" memory=", 1)[1].split("\n", 1)[0]
        def observed(argv):
            return eval(expression, {"argv": argv})
        self.assertEqual([b"6144"], observed([b"-m", b"6144"]))
        self.assertNotEqual([b"6144"], observed([b"-m", b"4096"]))
        self.assertNotEqual([b"6144"], observed([b"-m", b"6144", b"-m", b"2048"]))

    def test_qmp_listener_and_owned_connected_socket_census(self):
        source = boot._REMOTE.split("def qmp_socket_owned(lines,fds):", 1)[1].split("def source():", 1)[0]
        namespace = {"QMP": "/guest/qmp.sock"}
        exec("def qmp_socket_owned(lines,fds):" + source, namespace)
        listener = "00000000: 00000002 00000000 00010000 0001 01 100 /guest/qmp.sock"
        connected = "00000000: 00000003 00000000 00000000 0001 03 101 /guest/qmp.sock"
        foreign = "00000000: 00000003 00000000 00000000 0001 03 102 /guest/qmp.sock"
        fds = {"4": "socket:[100]", "5": "socket:[101]"}
        self.assertTrue(namespace["qmp_socket_owned"]([listener, connected], fds))
        self.assertFalse(namespace["qmp_socket_owned"]([listener, connected, foreign], fds))
        self.assertFalse(namespace["qmp_socket_owned"]([listener, listener.replace(" 100 ", " 103 ")],
                                                        {**fds, "6": "socket:[103]"}))

    def test_pre_effect_closure_refuses_orphan_frame_or_reset_receipt(self):
        source = boot._REMOTE.split("def closure_sample():", 1)[1].split("def phase_evidence(", 1)[0]
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            receipt_paths = {name: str(base / name.lower()) for name in
                             ("INTENT", "BEFORE", "RESET", "KEY_INTENT", "KEY_ACK", "AFTER", "PRE_FRAME", "POST_FRAME")}
            Path(receipt_paths["INTENT"]).write_text("original intent remains")
            owner = {"qemuPid": 9, "qemuStartTicks": 12, "diskDevice": 5, "diskInode": 6,
                     "isoDevice": 5, "isoInode": 7}
            media = {"sha256": "a" * 64, "device": 5, "inode": 7}
            disk = {"allocatedGuestClusters": 0, "device": 5, "inode": 6}
            namespace = {"os": os, **receipt_paths, "claim": lambda: owner,
                         "source": lambda: media, "blank_disk": lambda: disk,
                         "same_media": lambda observed: True,
                         "validate_receipts": lambda *args: {"state": "intent-only"},
                         "qmp_handshake": lambda observed: {"state": "ready", "phase": "complete",
                                                            "peerChecks": {"pid": True, "uid": True,
                                                                           "startTicks": True, "claim": True}}}
            exec("def closure_sample():" + source, namespace)
            self.assertEqual("intent-only", namespace["closure_sample"]()["state"])
            Path(receipt_paths["PRE_FRAME"]).write_bytes(b"orphan")
            with self.assertRaisesRegex(ValueError, "pre-effect-evidence"):
                namespace["closure_sample"]()
            Path(receipt_paths["PRE_FRAME"]).unlink()
            Path(receipt_paths["RESET"]).write_text("{}")
            with self.assertRaisesRegex(ValueError, "pre-effect-evidence"):
                namespace["closure_sample"]()

    def test_pre_effect_closure_refuses_changed_second_sample_before_marker(self):
        source = boot._program(boot.FIRST_CORRELATION, "close-start", CORR).split(
            "elif MODE=='close-start':", 1)[1].split("elif MODE=='close-preflight':", 1)[0]
        action = "def action():\n" + textwrap.indent(textwrap.dedent(source), " ")
        first = {"owner": {"qemuPid": 9}, "media": {"sha256": "a" * 64},
                 "blankDisk": {"allocatedGuestClusters": 0}}
        second = {**first, "owner": {"qemuPid": 10}}
        samples = iter((first, second))
        writes = []
        clock = iter((1_000_000_000, 2_000_000_000))
        namespace = {"CORR": boot.FIRST_CORRELATION, "CLOSE_CORR": CORR, "ATTEMPT": 1,
                     "ORIGINAL_CORR": boot.FIRST_CORRELATION,
                     "CLOSED": "/nonexistent/closure", "os": os,
                     "closure_sample": lambda: next(samples),
                     "verify_first_closed": lambda *args: None,
                     "time": types.SimpleNamespace(monotonic_ns=lambda: next(clock), sleep=lambda _: None),
                     "record": lambda *args: writes.append(args),
                     "hashlib": __import__("hashlib"), "json": json}
        exec(action, namespace)
        with self.assertRaisesRegex(ValueError, "closure-samples-changed"):
            namespace["action"]()
        self.assertEqual([], writes)

    def test_closure_response_loss_cannot_replay_or_be_called_without_original_intent(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(boot, "_reservation"), \
                mock.patch.object(boot.setup, "status", return_value={"state": "running-observed"}), \
                mock.patch.object(boot, "_remote", side_effect=subprocess.TimeoutExpired("ssh", 90)) as remote:
            with self.assertRaises(FileNotFoundError):
                boot.close_start(root, host="archlinux", closure_correlation_id=CORR)
            remote.assert_not_called()
            original = boot._intent(root, create=True)
            boot._save(original, boot.FIRST_CORRELATION)
            result = boot.close_start(root, host="archlinux", closure_correlation_id=CORR)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "closure intent exists"):
                boot.close_start(root, host="archlinux", closure_correlation_id=CORR)
            self.assertEqual(1, remote.call_count)
            self.assertEqual("unknown", boot.close_status(root, host="archlinux",
                                                          closure_correlation_id=CORR)["state"])

    def test_qmp_foreign_peer_and_generation_swap_block_before_reset(self):
        source = boot._REMOTE.split("def qmp_open(owner):", 1)[1].split("def expected(", 1)[0]
        owner = {"qemuPid": 9, "qemuStartTicks": 12}
        class Stream:
            def __init__(self):
                self.writes = []
                self.lines = [b'{"QMP":{}}\n', b'{"return":{}}\n']
            def readline(self, limit):
                return self.lines.pop(0)
            def write(self, data):
                self.writes.append(data)
        class Socket:
            def __init__(self, peer_pid):
                self.peer_pid = peer_pid
                self.stream = Stream()
            def settimeout(self, value):
                pass
            def connect(self, path):
                pass
            def getsockopt(self, level, key, length):
                return struct.pack("3i", self.peer_pid, os.geteuid(), os.getegid())
            def makefile(self, *args, **kwargs):
                return self.stream
        fake = Socket(99)
        sockets = types.SimpleNamespace(AF_UNIX=1, SOL_SOCKET=2, SO_PEERCRED=3, socket=lambda _: fake)
        namespace = {"socket": sockets, "struct": struct, "os": os, "json": json, "QMP": "/tmp/qmp",
                     "claim": lambda: owner, "ticks": lambda pid: 12}
        exec("def qmp_open(owner):" + source, namespace)
        with self.assertRaisesRegex(ValueError, "qmp-peer"):
            namespace["qmp_open"](owner)
        self.assertEqual([], fake.stream.writes)
        fake = Socket(9)
        sockets.socket = lambda _: fake
        ticks = {"value": 12}
        namespace["ticks"] = lambda pid: ticks["value"]
        sock, command = namespace["qmp_open"](owner)
        self.assertIs(sock, fake)
        self.assertEqual(1, len(fake.stream.writes))  # capabilities only
        ticks["value"] = 13
        with self.assertRaisesRegex(ValueError, "qmp-peer-changed"):
            command("system_reset")
        self.assertEqual(1, len(fake.stream.writes))

    def test_blank_disk_rejects_allocated_guest_cluster_and_backing_file(self):
        source = boot._REMOTE.split("def blank_disk():", 1)[1].split("def write_all(", 1)[0]
        with tempfile.TemporaryDirectory() as root:
            disk = Path(root) / "disk.qcow2"
            def make(backing=0, allocated=False):
                data = bytearray(4096)
                data[:4] = b"QFI\xfb"
                struct.pack_into(">I", data, 4, 3)
                struct.pack_into(">Q", data, 8, backing)
                struct.pack_into(">I", data, 20, 16)
                struct.pack_into(">Q", data, 24, 96 * 1024**3)
                struct.pack_into(">I", data, 36, 1)
                struct.pack_into(">Q", data, 40, 2048)
                if allocated:
                    struct.pack_into(">Q", data, 2048, 4096)
                disk.write_bytes(data)
            namespace = {"os": os, "stat": stat, "struct": struct, "DISK": str(disk)}
            exec("def blank_disk():" + source, namespace)
            make()
            self.assertEqual(0, namespace["blank_disk"]()["allocatedGuestClusters"])
            make(allocated=True)
            with self.assertRaisesRegex(ValueError, "disk-not-blank"):
                namespace["blank_disk"]()
            make(backing=1)
            with self.assertRaisesRegex(ValueError, "disk-not-blank"):
                namespace["blank_disk"]()

    def test_foreign_reservation_refuses_before_remote_action(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(boot, "_remote") as remote, \
                mock.patch.object(boot.native_environment, "_require_private"), \
                mock.patch.object(boot.native_environment, "_load") as load:
            load.return_value = {"reservations": [{"id": boot.RESERVATION_ID,
                "hostAlias": "archlinux", "environment": boot.setup.ENVIRONMENT,
                "operator": "foreign", "requestedMemoryBytes": boot.setup.MEMORY_MIB * 1024**2,
                "allocationState": "pending"}]}
            with self.assertRaisesRegex(ValueError, "reservation changed"):
                boot.start(root, host="archlinux", correlation_id=CORR)
            remote.assert_not_called()

    def test_preflight_rejects_foreign_running_vm(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(boot, "_reservation"), \
                mock.patch.object(boot.setup, "status", return_value={"state": "unknown"}), \
                mock.patch.object(boot, "_remote") as remote:
            with self.assertRaisesRegex(ValueError, "not running-observed"):
                boot.preflight(root, host="archlinux", correlation_id=CORR)
            remote.assert_not_called()

    def test_ready_response_requires_exact_owner_media_and_blank_disk(self):
        owner = {"qemuPid": 9, "qemuStartTicks": 12, "diskDevice": 6, "diskInode": 7,
                 "isoDevice": 8, "isoInode": 10}
        ready = {"schemaVersion": 1, "correlationId": CORR, "state": "ready", "nativeActionAllowed": False,
                 "reservationId": boot.RESERVATION_ID, "owner": owner,
                 "blankDisk": {"device": 6, "inode": 7, "virtualSizeBytes": 96 * 1024**3,
                               "allocatedGuestClusters": 0},
                 "media": {"device": 8, "inode": 10, "sizeBytes": boot.setup.WINDOWS_SIZE,
                           "mtimeNs": 2, "ctimeNs": 3, "sha256": boot.setup.WINDOWS_SHA256}}
        config = mock.Mock(hosts={"archlinux": object()})
        with mock.patch.object(boot.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(boot.ssh_transport, "connection_host", return_value=mock.Mock(password=None)), \
                mock.patch.object(boot.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
                mock.patch.object(boot.subprocess, "run") as run:
            for bad in ({**ready, "owner": {}},
                        {**ready, "blankDisk": {**ready["blankDisk"], "inode": 22}},
                        {**ready, "media": {**ready["media"], "sha256": "f" * 64}}):
                run.return_value = mock.Mock(returncode=0, stdout=json.dumps(bad).encode())
                with self.assertRaisesRegex(ValueError, "incomplete|owner"):
                    boot._remote("/tmp", "archlinux", CORR, "preflight", 60)
            run.return_value = mock.Mock(returncode=0, stdout=json.dumps(ready).encode())
            self.assertEqual("ready", boot._remote("/tmp", "archlinux", CORR, "preflight", 60)["state"])

    def test_short_local_intent_prevents_remote_reset_and_replay(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(boot, "_reservation"), \
                mock.patch.object(boot.setup, "status", return_value={"state": "running-observed"}), \
                mock.patch.object(boot, "_remote") as remote:
            original = os.write
            calls = 0
            def broken(fd, data):
                nonlocal calls
                calls += 1
                return original(fd, bytes(data[:2])) if calls == 1 else 0
            with mock.patch.object(boot.os, "write", side_effect=broken):
                with self.assertRaisesRegex(OSError, "short write"):
                    boot.start(root, host="archlinux", correlation_id=CORR)
            remote.assert_not_called()
            with self.assertRaisesRegex(ValueError, "intent exists"):
                boot.start(root, host="archlinux", correlation_id=CORR)
            remote.assert_not_called()

    def test_response_loss_cannot_replay_one_shot_action(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(boot, "_reservation"), \
                mock.patch.object(boot.setup, "status", return_value={"state": "running-observed"}), \
                mock.patch.object(boot, "_remote", side_effect=subprocess.TimeoutExpired("ssh", 90)) as remote:
            result = boot.start(root, host="archlinux", correlation_id=CORR)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "intent exists"):
                boot.start(root, host="archlinux", correlation_id=CORR)
            remote.assert_called_once()

    def test_empty_key_ack_never_claims_key_acknowledged(self):
        snippet = boot._REMOTE.split("def validate_receipts(owner,media,disk):", 1)[1].split("try:\n owner=", 1)[0]
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            paths = [base / name for name in ("intent", "before", "reset", "key-intent", "key-ack", "after")]
            owner = {"qemuPid": 9, "qemuStartTicks": 12}
            media = {"sha256": "a" * 64}
            disk = {"allocatedGuestClusters": 0}
            expected = {"schemaVersion": 1, "correlationId": CORR, "vmCorrelationId": boot.VM_CORRELATION,
                        "reservationId": boot.RESERVATION_ID, "owner": owner, "media": media, "blankDisk": disk,
                        "resetDelayMs": boot.DELAY_MS, "holdMs": boot.HOLD_MS, "postDelayMs": boot.POST_MS}
            def write(index, value):
                paths[index].write_text(json.dumps(value))
            write(0, expected)
            frame = {"sha256": "f" * 64, "width": 640, "height": 480, "sizeBytes": 100}
            write(1, {"schemaVersion": 1, "correlationId": CORR, "owner": owner, "frame": frame})
            write(2, {"schemaVersion": 1, "correlationId": CORR, "owner": owner, "phase": "reset-ack"})
            write(3, {"schemaVersion": 1, "correlationId": CORR, "owner": owner, "phase": "key-intent"})
            paths[4].write_text("{}")
            namespace = {"os": os, "INTENT": str(paths[0]), "BEFORE": str(paths[1]), "RESET": str(paths[2]),
                         "KEY_INTENT": str(paths[3]), "KEY_ACK": str(paths[4]), "AFTER": str(paths[5]),
                         "PRE_FRAME": "unused", "POST_FRAME": "unused", "CORR": CORR,
                         "read": lambda path: json.loads(Path(path).read_text()), "expected": lambda *args: expected,
                         "frame": lambda *args: frame}
            exec("def validate_receipts(owner,media,disk):" + snippet, namespace)
            with self.assertRaisesRegex(ValueError, "phase-receipt"):
                namespace["validate_receipts"](owner, media, disk)
            for index, path in enumerate(paths):
                if index != 2:
                    path.unlink(missing_ok=True)
            with self.assertRaisesRegex(ValueError, "orphan-boot-evidence"):
                namespace["validate_receipts"](owner, media, disk)
            paths[2].unlink()
            post_frame = base / "after.ppm"
            post_frame.write_bytes(b"orphan")
            namespace["POST_FRAME"] = str(post_frame)
            with self.assertRaisesRegex(ValueError, "orphan-boot-evidence"):
                namespace["validate_receipts"](owner, media, disk)

    def test_status_phase_evidence_observes_fixed_frame_and_qmp_only(self):
        source = boot._REMOTE.split("def phase_evidence(owner):", 1)[1].split("try:\n owner=", 1)[0]
        self.assertNotIn("screendump", source)
        self.assertNotIn("system_reset", source)
        self.assertNotIn("send-key", source)
        with tempfile.TemporaryDirectory() as root:
            pre = Path(root) / "pre.ppm"
            post = Path(root) / "post.ppm"
            pre.write_bytes(b"")
            pre.chmod(0o600)
            owner = {"qemuPid": 9}
            namespace = {"os": os, "stat": stat, "PRE_FRAME": str(pre), "POST_FRAME": str(post),
                         "qmp_handshake": lambda observed: {"state": "ready", "phase": "complete", "peerChecks": {"pid": True, "uid": True, "startTicks": True, "claim": True}},
                         "frame": lambda *args: (_ for _ in ()).throw(AssertionError("empty frame read"))}
            exec("def phase_evidence(owner):" + source, namespace)
            result = namespace["phase_evidence"](owner)
            self.assertEqual("zero-byte", result["preFrame"]["state"])
            self.assertEqual("absent", result["postFrame"]["state"])
            self.assertEqual("complete", result["qmpHandshake"]["phase"])
            self.assertEqual(b"", pre.read_bytes())
            namespace["qmp_handshake"] = lambda observed: {"state": "unknown", "phase": "peer", "reason": "peer-mismatch"}
            self.assertEqual("peer-mismatch", namespace["phase_evidence"](owner)["qmpHandshake"]["reason"])

    def test_qmp_status_handshake_labels_peer_and_capability_failure_without_input(self):
        source = boot._REMOTE.split("def qmp_handshake(owner):", 1)[1].split("def phase_evidence(", 1)[0]
        self.assertNotIn("screendump", source)
        self.assertNotIn("system_reset", source)
        self.assertNotIn("send-key", source)
        class Stream:
            def __init__(self, lines):
                self.lines = list(lines)
                self.writes = []
            def readline(self, limit):
                return self.lines.pop(0)
            def write(self, data):
                self.writes.append(data)
        class Socket:
            def __init__(self, pid, lines):
                self.pid = pid
                self.stream = Stream(lines)
            def settimeout(self, seconds):
                pass
            def connect(self, path):
                pass
            def getsockopt(self, level, key, size):
                return struct.pack("3i", self.pid, os.geteuid(), os.getegid())
            def makefile(self, *args, **kwargs):
                return self.stream
            def close(self):
                pass
        owner = {"qemuPid": 9, "qemuStartTicks": 12}
        fake = Socket(99, [])
        sockets = types.SimpleNamespace(AF_UNIX=1, SOL_SOCKET=2, SO_PEERCRED=3,
                                        timeout=TimeoutError, socket=lambda _: fake)
        namespace = {"socket": sockets, "struct": struct, "os": os, "json": json,
                     "QMP": "/tmp/qmp", "ticks": lambda pid: 12, "claim": lambda: owner}
        exec("def qmp_handshake(owner):" + source, namespace)
        first = namespace["qmp_handshake"](owner)
        self.assertEqual("peer", first["phase"])
        self.assertEqual("peer-mismatch", first["reason"])
        self.assertFalse(first["peerChecks"]["pid"])
        self.assertEqual([], fake.stream.writes)
        fake = Socket(9, [b'{"QMP":{}}\n', b'{"error":{"class":"GenericError"}}\n'])
        sockets.socket = lambda _: fake
        second = namespace["qmp_handshake"](owner)
        self.assertEqual("capabilities", second["phase"])
        self.assertEqual("capabilities-error", second["reason"])
        self.assertTrue(all(second["peerChecks"].values()))
        self.assertEqual([b'{"execute":"qmp_capabilities"}\r\n'], fake.stream.writes)
        before = len(fake.stream.writes)
        namespace["claim"] = lambda: (_ for _ in ()).throw(ValueError("qemu-fd"))
        third = namespace["qmp_handshake"](owner)
        self.assertEqual("peer-claim", third["phase"])
        self.assertEqual("claim-qemu-fd", third["reason"])
        self.assertIsNone(third["peerChecks"]["claim"])
        self.assertEqual(before, len(fake.stream.writes))


if __name__ == "__main__":
    unittest.main()

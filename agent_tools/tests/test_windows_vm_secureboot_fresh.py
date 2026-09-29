"""Source-only admission and non-replay coverage for the independent secure VM."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

from agent_tools import windows_vm_secureboot_fresh as subject


CORR = "123e4567-e89b-12d3-a456-426614174000"
IDENTITY = {"reservationId": "env-fixed", "token": "opaque", "hostAlias": "archlinux",
            "environment": subject.ENVIRONMENT, "operator": subject.OPERATOR}
RESERVATION = {"hostAlias": "archlinux", "environment": subject.ENVIRONMENT,
               "operator": subject.OPERATOR, "requestedMemoryBytes": subject.MEMORY_MIB * 1024 * 1024,
               "allocationState": "pending", "reservationIdentity": IDENTITY}


def program(**changes):
    values = {"ROOT": subject.ROOT, "GUEST": subject.GUEST, "MODE": "preflight"}
    values.update(changes)
    text = subject._program(CORR, values.pop("MODE"))
    for key in ("ROOT", "GUEST"):
        text = text.replace(repr(getattr(subject, key)), repr(values[key]))
    return text


class WindowsVmSecurebootFreshTest(unittest.TestCase):
    def test_fixed_program_only_uses_official_media_and_new_blank_disk(self):
        remote = subject._program(CORR, "start")
        compile(remote, "<secureboot-fresh>", "exec")
        self.assertIn(subject.WINDOWS_SHA256, remote)
        self.assertIn(subject.DRIVER_SHA256, remote)
        self.assertIn(subject.CODE_SHA256, remote)
        self.assertIn(subject.VARS_SHA256, remote)
        self.assertIn("'/usr/bin/qemu-img','create','-f','qcow2'", remote)
        self.assertIn("'--enroll-microsoft'", remote)
        self.assertIn("'--secure-boot'", remote)
        self.assertIn("'--tpm2'", remote)
        self.assertIn("'tpm-tis,tpmdev=tpm0'", remote)
        self.assertNotIn("vpn-control-windows-baseline-20260929/guest/disk.qcow2", remote)
        self.assertNotIn("vpn-control-windows-native-20260907/guest", remote)
        self.assertNotIn("subprocess.run(['kill'", remote)

    def test_missing_key_enrollment_tool_blocks_before_disk_or_guest_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = str(Path(directory) / "new-private-vm")
            guest = root + "/guest"
            script = program(ROOT=root, GUEST=guest)
            script = script.replace("'/usr/bin/virt-fw-vars'", repr(str(Path(directory) / "missing-fw-vars")))
            result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value["state"], "blocked")
            self.assertEqual(value["reason"], "virt-fw-vars-unavailable")
            self.assertFalse(value["nativeActionAllowed"])
            self.assertFalse(Path(root).exists())

    def test_failed_package_integrity_blocks_preflight_before_guest_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "new-private-vm"
            scope: dict = {}
            exec(program(ROOT=str(root), GUEST=str(root / "guest")).split(
                "try:\n if MODE=='status'", 1)[0], scope)
            scope["binary"] = lambda name: "/usr/bin/" + name
            def package_check(argv, **_):
                if argv[1] == "-Q":
                    return subprocess.CompletedProcess(argv, 0, b"virt-firmware 26.9-1\n", b"")
                self.assertEqual(argv[1:], ["-Qkk", "virt-firmware"])
                return subprocess.CompletedProcess(argv, 1, b"altered files\n", b"")
            with (mock.patch("os.path.isfile", return_value=True),
                  mock.patch("subprocess.run", side_effect=package_check) as dispatched):
                reason, _, _ = scope["prerequisites"]()
            self.assertEqual(reason, "virt-fw-vars-unavailable")
            self.assertEqual(dispatched.call_count, 2)
            self.assertFalse(root.exists())

    def test_existing_target_root_blocks_without_touching_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "new-private-vm"
            root.mkdir()
            marker = root / "owner-marker"
            marker.write_bytes(b"preserve")
            script = program(ROOT=str(root), GUEST=str(root / "guest"))
            result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5)
            self.assertEqual(json.loads(result.stdout)["reason"], "guest-root-exists")
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_start_reserves_after_local_intent_and_never_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            with (mock.patch.object(subject, "_remote", return_value={"state": "running-observed", "reason": None}) as remote,
                  mock.patch.object(subject.native_environment, "reserve_environment",
                                    return_value={"state": "reserved", "identity": IDENTITY,
                                                  "reservation": {"allocationState": "pending"}}) as reserve):
                def after_intent(*_):
                    self.assertTrue(subject._intent(directory, create=False).exists())
                    return {"state": "reserved", "identity": IDENTITY,
                            "reservation": {"allocationState": "pending"}}
                reserve.side_effect = after_intent
                result = subject.start(directory, host="archlinux", correlation_id=CORR,
                                       reservation_request=RESERVATION)
                self.assertEqual(result["state"], "running-observed")
                self.assertFalse(result["replayAllowed"])
                with self.assertRaisesRegex(ValueError, "intent exists"):
                    subject.start(directory, host="archlinux", correlation_id=CORR,
                                  reservation_request=RESERVATION)
                reserve.assert_called_once()
                remote.assert_called_once_with(directory, CORR, "start", 300)

    def test_unknown_start_preserves_intent_for_exact_status(self):
        with tempfile.TemporaryDirectory() as directory:
            with (mock.patch.object(subject, "_remote", side_effect=subprocess.TimeoutExpired("ssh", 30)),
                  mock.patch.object(subject.native_environment, "reserve_environment",
                                    return_value={"state": "reserved", "identity": IDENTITY,
                                                  "reservation": {"allocationState": "pending"}})):
                result = subject.start(directory, host="archlinux", correlation_id=CORR,
                                       reservation_request=RESERVATION)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])
            with mock.patch.object(subject, "_remote", return_value={"state": "partial-unknown", "reason": None}):
                self.assertEqual(subject.status(directory, host="archlinux", correlation_id=CORR)["state"], "partial-unknown")
                with self.assertRaisesRegex(ValueError, "intent changed"):
                    subject.status(directory, host="archlinux",
                                   correlation_id="123e4567-e89b-12d3-a456-426614174001")

    def test_wrong_reservation_cannot_create_local_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(subject, "_remote") as remote:
                with self.assertRaisesRegex(ValueError, "separate exact pending reservation"):
                    subject.start(directory, host="archlinux", correlation_id=CORR,
                                  reservation_request={**RESERVATION, "environment": "windows-vm-baseline-20260929"})
                remote.assert_not_called()
                self.assertFalse((Path(directory) / ".rag_index").exists())

    def test_status_rejects_unrelated_disk_even_with_matching_process_generations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "new-private-vm"
            guest = root / "guest"
            tpm = guest / "tpm"
            tpm.mkdir(parents=True, mode=0o700)
            for path in (root, guest, tpm):
                path.chmod(0o700)
            text = program(ROOT=str(root), GUEST=str(guest), MODE="status")
            scope: dict = {}
            exec(text.split("try:\n if MODE=='status'", 1)[0], scope)
            disk = str(guest / "disk.qcow2")
            vars_path = guest / "uefi-vars.fd"
            vars_path.write_bytes(b"private-vars")
            vars_path.chmod(0o600)
            for name, value in (
                ("intent.json", {"schemaVersion": 1, "correlationId": CORR,
                                 "windowsSha256": subject.WINDOWS_SHA256,
                                 "driverSha256": subject.DRIVER_SHA256,
                                 "codeSha256": subject.CODE_SHA256,
                                 "varsTemplateSha256": subject.VARS_SHA256,
                                 "disk": disk, "vars": str(vars_path),
                                 "tpmSocket": str(tpm / "swtpm.sock"),
                                 "memoryMiB": subject.MEMORY_MIB, "vncPort": subject.VNC_PORT}),
                ("qemu-started.json", {"pid": 77, "startTicks": 123}),
                ("swtpm-started.json", {"pid": 88, "startTicks": 456})):
                path = guest / name
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            active_socket = socket.socket(socket.AF_UNIX)
            active_socket.bind(str(tpm / "swtpm.sock"))
            self.addCleanup(active_socket.close)
            scope["ticks"] = lambda pid: {77: 123, 88: 456}.get(pid)
            scope["owned_disk"] = lambda pid: True
            scope["socket_owned"] = lambda pid, path: True
            scope["enrolled_vars"] = lambda path: True
            scope["executable"] = lambda pid, path: True
            qargs = scope["qemu_args"]()
            targs = scope["swtpm_args"]()
            scope["args"] = lambda pid: qargs if pid == 77 else targs
            self.assertEqual(scope["state"](), "running-observed")
            qargs += ["-drive", "file=/home/kardinal/CP117/disk.qcow2,if=virtio,format=qcow2"]
            self.assertEqual(scope["state"](), "unknown")
            qargs = scope["qemu_args"]()
            qargs[qargs.index("-vnc") + 1] = "127.0.0.1:99"
            self.assertEqual(scope["state"](), "unknown")
            qargs = scope["qemu_args"]()
            qargs[qargs.index("-m") + 1] = "8192"
            self.assertEqual(scope["state"](), "unknown")
            qargs = scope["qemu_args"]()
            targs = scope["swtpm_args"]()
            targs[targs.index("--tpm2")] = "--tpm1"
            self.assertEqual(scope["state"](), "unknown")

    def test_key_enrollment_requires_pk_kek_db_and_secure_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vars.fd"
            path.write_bytes(b"vars")
            path.chmod(0o600)
            scope: dict = {}
            exec(subject._program(CORR, "status").split("try:\n if MODE=='status'", 1)[0], scope)
            variables = [{"name": name, "data": data} for name, data in (
                ("PK", "ab" * 100), ("KEK", "cd" * 100), ("db", "ef" * 100),
                ("SecureBootEnable", "01"), ("CustomMode", "00"))]
            receipt = {"version": 2, "variables": variables}
            actual_parser = scope["cert_fingerprints"]
            scope["cert_fingerprints"] = lambda data: {
                "ab" * 100: scope["MICROSOFT"]["PK"],
                "cd" * 100: scope["MICROSOFT"]["KEK"],
                "ef" * 100: scope["MICROSOFT"]["db"]}[data]
            with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(receipt).encode(), b"")):
                self.assertTrue(scope["enrolled_vars"](str(path)))
            scope["cert_fingerprints"] = actual_parser
            with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(receipt).encode(), b"")):
                with self.assertRaises(ValueError):
                    scope["enrolled_vars"](str(path))
            variables[2]["data"] = "ef" * 100
            variables[3]["data"] = "00"
            with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(receipt).encode(), b"")):
                with self.assertRaises(ValueError):
                    scope["enrolled_vars"](str(path))
            variables[2]["data"] = ""
            with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(receipt).encode(), b"")):
                with self.assertRaises(ValueError):
                    scope["enrolled_vars"](str(path))

    def test_signature_parser_rejects_non_microsoft_owner_and_wrong_certificate(self):
        scope: dict = {}
        exec(subject._program(CORR, "status").split("try:\n if MODE=='status'", 1)[0], scope)
        fake_cert = b"not-a-Microsoft-certificate"
        stride = 16 + len(fake_cert)
        def signature(owner: uuid.UUID) -> str:
            return (scope["X509"].bytes_le + struct.pack("<LLL", 28 + stride, 0, stride)
                    + owner.bytes_le + fake_cert).hex()
        wrong_owner = signature(uuid.uuid4())
        with self.assertRaises(ValueError):
            scope["cert_fingerprints"](wrong_owner)
        result = scope["cert_fingerprints"](signature(scope["MS_OWNER"]))
        self.assertEqual(len(result), 1)
        self.assertNotEqual(result, scope["MICROSOFT"]["PK"])

    def test_real_held_disk_and_qmp_tpm_socket_inode_checks_reject_foreign_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            (proc / "net").mkdir(parents=True)
            for pid in (77, 88):
                (proc / str(pid) / "fd").mkdir(parents=True)
            disk = root / "disk.qcow2"
            disk.write_bytes(b"blank-qcow2")
            disk.chmod(0o600)
            (proc / "77/fd/5").symlink_to(disk)
            qmp = root / "qmp.sock"
            tpm = root / "swtpm.sock"
            (proc / "77/fd/6").symlink_to("socket:[44]")
            (proc / "88/fd/7").symlink_to("socket:[55]")
            (proc / "77/exe").symlink_to("/usr/bin/qemu-system-x86_64")
            (proc / "88/exe").symlink_to("/usr/bin/swtpm")
            (proc / "net/unix").write_text(
                "Num RefCount Protocol Flags Type St Inode Path\n"
                + "00000000: 00000002 00000000 00010000 0001 01 44 " + str(qmp) + "\n"
                + "00000000: 00000002 00000000 00010000 0001 01 55 " + str(tpm) + "\n")
            script = subject._program(CORR, "status").split("try:\n if MODE=='status'", 1)[0]
            script = script.replace("/proc", str(proc))
            scope: dict = {}
            exec(script, scope)
            scope["DISK"] = str(disk)
            self.assertTrue(scope["owned_disk"](77))
            self.assertTrue(scope["socket_owned"](77, str(qmp)))
            self.assertTrue(scope["socket_owned"](88, str(tpm)))
            self.assertTrue(scope["executable"](77, "/usr/bin/qemu-system-x86_64"))
            (proc / "77/exe").unlink()
            (proc / "77/exe").symlink_to("/usr/bin/unrelated-qemu")
            self.assertFalse(scope["executable"](77, "/usr/bin/qemu-system-x86_64"))
            (proc / "88/fd/7").unlink()
            (proc / "88/fd/7").symlink_to("socket:[other]")
            self.assertFalse(scope["socket_owned"](88, str(tpm)))
            unrelated = root / "unrelated.qcow2"
            unrelated.write_bytes(b"foreign")
            (proc / "77/fd/5").unlink()
            (proc / "77/fd/5").symlink_to(unrelated)
            self.assertFalse(scope["owned_disk"](77))


if __name__ == "__main__":
    unittest.main()

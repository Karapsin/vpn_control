"""Causal read-only inventory for the Windows 11 Setup requirements block."""
from __future__ import annotations

import json
import contextlib
import io
import os
from pathlib import Path
import tempfile
import hashlib
import stat
import unittest
from unittest import mock
from types import SimpleNamespace

from agent_tools import windows_vm_secureboot_inventory as inventory


def observation(*, tpm=False, secure=False, components=None):
    return {
        "schemaVersion": 1, "host": "archlinux", "qemuPid": 3369984,
        "startTicks": 45177745, "diskOwned": True, "qmpSocketOwned": True,
        "currentTpmDevice": tpm, "currentSecureFirmware": secure,
        "firmwareCodePath": "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
        "firmwareVarsPath": "/home/kardinal/vpn-control-windows-baseline-20260929/guest/OVMF_VARS.fd",
        "components": components or {"binaries": [], "firmware": [], "packages": []},
    }


class WindowsVmSecurebootInventoryTest(unittest.TestCase):
    def test_remote_proc_argv_requires_linked_task_owned_tpm_and_ignores_path_pacman(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = root / "guest"; guest.mkdir()
            disk = guest / "disk.qcow2"; disk.write_bytes(b"qcow2")
            proc = root / "proc"; (proc / "9" / "fd").mkdir(parents=True); (proc / "net").mkdir()
            (proc / "9" / "stat").write_text("9 (qemu) S " + "0 " * 18 + "12\n")
            (proc / "9" / "fd" / "4").symlink_to(disk)
            (proc / "9" / "fd" / "5").symlink_to("socket:[55]")
            (proc / "net" / "unix").write_text("000: 02 00 10000 0001 01 55 " + str(guest / "qmp.sock") + "\n")
            bin_dir = root / "untrusted-bin"; bin_dir.mkdir()
            marker = root / "path-pacman-ran"
            attack = bin_dir / "pacman"
            attack.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
            attack.chmod(0o755)
            source = inventory._REMOTE.replace("PID=3369984;TICKS=45177745", "PID=9;TICKS=12")
            source = source.replace(inventory.GUEST, str(guest)).replace("'/proc", "'" + str(proc))
            source = source.replace("'/usr/bin/", "'" + str(root / "trusted-bin") + "/")
            source = source.replace("ROOTS=('/usr/share/edk2/x64','/usr/share/OVMF','/usr/share/qemu')",
                                    "ROOTS=(" + repr(str(root / "firmware")) + ",)")
            def execute(extra):
                argv = [b"qemu-system-x86_64", b"-drive", ("file=" + str(disk) + ",if=virtio").encode(),
                        b"-drive", ("if=pflash,file=" + str(root / "firmware" / "OVMF_CODE.4m.fd")).encode(),
                        *[item.encode() for item in extra]]
                (proc / "9" / "cmdline").write_bytes(b"\0".join(argv) + b"\0")
                output = io.StringIO()
                with mock.patch.dict(os.environ, {"PATH": str(bin_dir)}), contextlib.redirect_stdout(output):
                    exec(source, {"__name__": "__main__"})
                return json.loads(output.getvalue())
            unrelated = ["-chardev", "socket,id=char1,path=" + str(guest / "tpm.sock"),
                         "-tpmdev", "emulator,id=tpm2,chardev=char1",
                         "-device", "tpm-tis,tpmdev=tpm1"]
            self.assertFalse(execute(unrelated)["currentTpmDevice"])
            linked = unrelated[:-1] + ["tpm-tis,tpmdev=tpm2"]
            self.assertTrue(execute(linked)["currentTpmDevice"])
            self.assertFalse(marker.exists())

    def test_firmware_hash_rejects_path_stat_lie_and_oversized_open_descriptor(self):
        source = inventory._REMOTE.split("def file_info(path):\n", 1)[1].split("\ndef output", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "OVMF_CODE.secboot.fd"
            with path.open("wb") as stream: stream.truncate(33554433)
            class FakeOs:
                path = os.path
                def stat(self, target):
                    actual = os.stat(target)
                    return type("SmallStat", (), {"st_mode": actual.st_mode,
                        "st_size": 1, "st_dev": actual.st_dev, "st_ino": actual.st_ino,
                        "st_mtime_ns": actual.st_mtime_ns})()
                def __getattr__(self, name): return getattr(os, name)
            namespace = {"os": FakeOs(), "stat": stat, "hashlib": hashlib,
                         "ROOTS": (directory,), "ValueError": ValueError}
            exec("def file_info(path):\n" + source, namespace)
            with self.assertRaises(ValueError): namespace["file_info"](str(path))

    def test_requirements_screen_is_explained_by_missing_current_tpm_and_secure_firmware(self):
        result = inventory.classify(observation())
        self.assertEqual(result["state"], "observed")
        self.assertFalse(result["currentGuestMeetsRequirements"])
        self.assertEqual(result["missingCurrentDevices"], ["tpm2", "secure-boot-firmware"])
        self.assertEqual(result["safeNextAction"], "prepare-stopped-secureboot-tpm-clone")
        self.assertFalse(result["nativeActionAllowed"])

    def test_a_capability_file_does_not_relabel_the_live_vm(self):
        components = {"binaries": [{"name": "swtpm", "path": "/usr/bin/swtpm", "sizeBytes": 1}],
                      "firmware": [{"path": "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
                                    "sizeBytes": 1, "sha256": "a" * 64}], "packages": []}
        result = inventory.classify(observation(components=components))
        self.assertFalse(result["currentGuestMeetsRequirements"])
        self.assertEqual(result["missingCurrentDevices"], ["tpm2", "secure-boot-firmware"])

    def test_wrong_generation_or_unowned_disk_is_unknown(self):
        for changed in ({"startTicks": 45177746}, {"diskOwned": False},
                        {"qmpSocketOwned": False}, {"currentTpmDevice": "false"}):
            with self.subTest(changed=changed):
                self.assertEqual(inventory.classify({**observation(), **changed})["state"], "unknown")

    def test_remote_program_is_fixed_and_bounded_transport(self):
        compile(inventory._REMOTE, "<secureboot-inventory>", "exec")
        fake_config = SimpleNamespace(hosts={"archlinux": object()})
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(observation()).encode())
        with mock.patch.object(inventory.ssh_transport, "load_config", return_value=fake_config), \
             mock.patch.object(inventory.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
             mock.patch.object(inventory.ssh_transport, "build_ssh_argv", return_value=["ssh", "archlinux"]) as argv, \
             mock.patch.object(inventory.subprocess, "run", return_value=completed) as run:
            result = inventory.observe(".", {"host": "archlinux", "qemuPid": 3369984,
                                             "startTicks": 45177745, "timeoutSeconds": 30})
        self.assertEqual(result["state"], "observed")
        self.assertEqual(argv.call_args.args[2], 30)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertFalse(run.call_args.kwargs["shell"] if "shell" in run.call_args.kwargs else False)

    def test_no_arbitrary_host_pid_or_timeout(self):
        for changed in ({"host": "other"}, {"qemuPid": 1}, {"startTicks": 1},
                        {"timeoutSeconds": 301}, {"extra": "x"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inventory.observe(".", {"host": "archlinux", "qemuPid": 3369984,
                                        "startTicks": 45177745, "timeoutSeconds": 30, **changed})

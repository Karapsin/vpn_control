"""Causal disk-topology admission for the disposable Windows installer."""
from __future__ import annotations

import io
import json
import os
import stat
import types
import unittest
from unittest import mock

from agent_tools import windows_vm_setup_install_disk_proof as proof


OWNER = {"qemuPid": 9, "qemuStartTicks": 12, "diskDevice": 2, "diskInode": 3,
         "isoDevice": 4, "isoInode": 5}
BLANK = {"device": 2, "inode": 3, "virtualSizeBytes": 96 * 1024**3, "allocatedGuestClusters": 0}


def fixture(extra: list[bytes] = (), foreign_inode: bool = False):
    guest = "/tmp/disposable-windows-guest"
    iso = "/tmp/windows-eval.iso"
    driver = "/tmp/virtio.iso"
    firmware = "/usr/share/edk2/x64/OVMF_CODE.fd"
    argv = [b"qemu-system-x86_64", b"-name", b"vpn-control-windows-setup-20260929",
            b"-machine", b"q35", b"-accel", b"kvm", b"-cpu", b"host", b"-smp", b"4", b"-m", b"6144",
            b"-drive", ("if=pflash,format=raw,readonly=on,file=" + firmware).encode(),
            b"-drive", ("if=pflash,format=raw,file=" + guest + "/uefi-vars.fd").encode(),
            b"-drive", ("file=" + guest + "/disk.qcow2,if=virtio,format=qcow2").encode(),
            b"-drive", ("file=" + iso + ",media=cdrom,readonly=on").encode(),
            b"-drive", ("file=" + driver + ",media=cdrom,readonly=on").encode(),
            b"-netdev", b"user,id=net0", b"-device", b"virtio-net-pci,netdev=net0",
            b"-display", b"none", b"-vnc", b"127.0.0.1:27", b"-monitor", b"none",
            b"-qmp", ("unix:" + guest + "/qmp.sock,server=on,wait=off").encode(), *extra]
    source = proof._program(OWNER).split("def install_disk_proof():", 1)[1].split("\ntry:\n print(json.dumps(install_disk_proof()", 1)[0]
    captured = {}
    def run():
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=os.geteuid(), st_nlink=1,
                                     st_size=10, st_dev=6, st_ino=7)
        fake_os = types.SimpleNamespace(stat=lambda *args, **kwargs: info,
                                        listdir=lambda path: ["4"],
                                        readlink=lambda path: guest + "/uefi-vars.fd",
                                        geteuid=os.geteuid)
        current = {"device": 2, "inode": 999 if foreign_inode else 3,
                   "virtualSizeBytes": 96 * 1024**3, "allocatedL1Entries": 2,
                   "backingFile": False, "snapshots": 0}
        namespace = {"keyboard_source": lambda: (OWNER, {}, BLANK, {}),
                     "keyboard_status": lambda *args: {"state": "after-observed", "frame": {"sha256": proof.INSTALL_FRAME_SHA256}},
                     "disk_metadata": lambda: current,
                     "read": lambda path: {"firmware": firmware} if path.endswith("/intent.json") else
                                   {"correlationId": proof.boot.FIRST_CORRELATION,
                                    "owner": OWNER, "blankDisk": BLANK},
                     "open": lambda *args, **kwargs: io.BytesIO(b"\0".join(argv) + b"\0"),
                     "os": fake_os, "stat": stat, "ticks": lambda pid: 12, "claim": lambda: OWNER,
                     "qmp_open": lambda owner: (types.SimpleNamespace(close=lambda: None), lambda name: []),
                     "live_blocks": lambda blocks: {"attachedBlockCount": 1,
                                                   "writableAttached": [guest + "/disk.qcow2"]},
                     "same_media": lambda media: True, "GUEST": guest, "ISO": iso, "DRIVER": driver,
                     "DISK": guest + "/disk.qcow2", "QMP": guest + "/qmp.sock",
                     "INSTALL_FRAME_SHA": proof.INSTALL_FRAME_SHA256,
                     "FIRST_BLANK_CORR": proof.boot.FIRST_CORRELATION}
        exec("def install_disk_proof():" + source, namespace)
        captured.update(namespace)
        return namespace["install_disk_proof"]()
    return run


class WindowsInstallDiskProofTest(unittest.TestCase):
    def test_unknown_remote_phase_is_typed_and_never_admits_install(self):
        prior = {"state": "after-observed", "owner": OWNER,
                 "frame": {"sha256": proof.INSTALL_FRAME_SHA256}}
        diagnostic = {"schemaVersion": 1, "state": "unknown", "phase": "qmp",
                      "reason": "qmp-foreign-block", "nativeActionAllowed": False}
        config = types.SimpleNamespace(hosts={"archlinux": object()})
        with mock.patch.object(proof.keyboard, "status", return_value=prior), \
                mock.patch.object(proof.boot.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(proof.boot.ssh_transport, "connection_host",
                                  return_value=types.SimpleNamespace(password=None)), \
                mock.patch.object(proof.boot.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
                mock.patch.object(proof.subprocess, "run",
                                  return_value=types.SimpleNamespace(returncode=0,
                                      stdout=json.dumps(diagnostic).encode())):
            result = proof.preflight(".", host="archlinux")
        self.assertEqual("unknown", result["state"])
        self.assertEqual("qmp", result["phase"])
        self.assertEqual("qmp-foreign-block", result["reason"])
        self.assertFalse(result["replayAllowed"])

    def test_hotplugged_foreign_block_is_rejected_by_live_qmp_census(self):
        source = proof._program(OWNER).split("def live_blocks(blocks):", 1)[1].split("\ndef install_disk_proof():", 1)[0]
        guest = "/tmp/disposable-windows-guest"
        namespace = {"DISK": guest + "/disk.qcow2", "ISO": "/tmp/windows-eval.iso",
                     "DRIVER": "/tmp/virtio.iso", "GUEST": guest,
                     "read": lambda path: {"firmware": "/usr/share/edk2/x64/OVMF_CODE.fd"}}
        exec("def live_blocks(blocks):" + source, namespace)
        good = {"inserted": {"file": guest + "/disk.qcow2", "ro": False,
                             "backing_file_depth": 0, "image": {}}}
        self.assertEqual([guest + "/disk.qcow2"], namespace["live_blocks"]([good])["writableAttached"])
        hotplug = {"inserted": {"file": "/dev/sda", "ro": False,
                                "backing_file_depth": 0, "image": {}}}
        with self.assertRaisesRegex(ValueError, "qmp-foreign-block"):
            namespace["live_blocks"]([good, hotplug])

    def test_only_blank_task_owned_disk_and_vars_are_admitted(self):
        result = fixture()()
        self.assertEqual("ready", result["state"])
        self.assertEqual(5, result["driveCount"])
        self.assertFalse(result["otherGuestOrHostDiskWritable"])

    def test_foreign_writable_drive_blocks_install_acknowledgment(self):
        with self.assertRaisesRegex(ValueError, "qemu-device-topology"):
            fixture([b"-drive", b"file=/dev/sda,if=virtio,format=raw"])()

    def test_same_original_disposable_disk_allows_later_guest_allocations(self):
        result = fixture()()
        self.assertEqual(2, result["installDisk"]["allocatedL1Entries"])
        self.assertEqual(BLANK, result["historicalBlankDisk"])

    def test_changed_disk_inode_blocks_install_acknowledgment(self):
        with self.assertRaisesRegex(ValueError, "disk-identity-changed"):
            fixture(foreign_inode=True)()

    def test_prior_page_hash_is_separate_from_install_option_hash(self):
        program = proof._program(OWNER)
        self.assertIn("KEYBOARD_SETUP_FRAME_SHA='" + proof.keyboard.SETUP_FRAME_SHA256 + "'", program)
        self.assertIn("INSTALL_FRAME_SHA='" + proof.INSTALL_FRAME_SHA256 + "'", program)


if __name__ == "__main__":
    unittest.main()

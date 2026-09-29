"""Causal tests for the fixed, read-only Arch QEMU holder census."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import arch_qemu_holder_census as census
from agent_tools import ssh_transport


class ArchQemuHolderCensusTest(unittest.TestCase):
    def test_observe_uses_safe_fixed_ssh_command_with_real_builder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = ssh_transport.SshHost(
                alias="archlinux", host="example.invalid", port=22, user="kardinal",
                identity_file=root / "identity", known_hosts_file=root / "known_hosts")
            config = ssh_transport.SshConfig(root=root, hosts={"archlinux": host})
            invoked = []

            def runner(argv, **kwargs):
                invoked.append(argv)
                payload = {"schemaVersion": 1, "host": "archlinux", "censusComplete": True,
                           "observedAtUnixMs": 1, "processes": [], "windowsBaselineReceipt": None}
                return subprocess.CompletedProcess(argv, 0, json.dumps(payload).encode(), b"")

            with patch.object(census.ssh_transport, "load_config", return_value=config), \
                    patch.object(census, "_read_local_claim", return_value=None):
                result = census.observe(root, {"host": "archlinux", "timeoutSeconds": 15},
                                        runner=runner)
            self.assertEqual(result["state"], "observed")
            self.assertEqual(len(invoked), 1)
            self.assertNotIn("\n", invoked[0][-1])
            self.assertNotIn("sudo", invoked[0][-1])

    def test_unreadable_live_qemu_fails_closed(self):
        raw = {"schemaVersion": 1, "host": "archlinux", "censusComplete": False,
               "processes": [{"pid": 41, "state": "unknown", "reason": "memory-unknown:4G,slots=4"}]}
        result = census.classify(raw, local_claim=None)
        self.assertFalse(result["inventoryComplete"])
        self.assertEqual(result["processes"][0]["claimedRole"], "unknown")
        self.assertEqual(result["processes"][0]["reason"], "memory-unknown:4G,slots=4")

    def test_prefix_disk_decoy_cannot_claim_windows_baseline(self):
        raw = {"schemaVersion": 1, "host": "archlinux", "censusComplete": True,
               "processes": [{"pid": 42, "startTicks": 99, "state": "observed",
                   "exe": "qemu-system-x86_64", "allocatedMemoryMiB": 6144,
                   "disks": [{"path": "/home/kardinal/vpn-control-windows-baseline-20260929/guest/disk.qcow2-other",
                              "device": 1, "inode": 2}], "qmpSockets": [{"path": "/home/kardinal/vpn-control-windows-baseline-20260929/guest/qmp.sock", "inode": 7}],
                   "tcpListeners": []}],
               "windowsBaselineReceipt": {"correlationId": "11111111-1111-4111-8111-111111111111",
                   "pid": 42, "startTicks": 99, "diskDevice": 1, "diskInode": 2}}
        local = {"correlationId": "11111111-1111-4111-8111-111111111111"}
        with self.assertRaises(ValueError):
            census.classify(raw, local_claim=local)

    def test_exact_receipt_disk_and_qmp_claim_windows_baseline(self):
        raw = {"schemaVersion": 1, "host": "archlinux", "censusComplete": True,
               "processes": [{"pid": 42, "startTicks": 99, "state": "observed",
                   "exe": "qemu-system-x86_64", "allocatedMemoryMiB": 6144,
                   "disks": [{"path": "/home/kardinal/vpn-control-windows-baseline-20260929/guest/disk.qcow2",
                              "device": 1, "inode": 2}], "qmpSockets": [{"path": "/home/kardinal/vpn-control-windows-baseline-20260929/guest/qmp.sock", "inode": 7}],
                   "tcpListeners": [{"inode": 8, "port": 5927, "bindAddress": "127.0.0.1"}]}],
               "windowsBaselineReceipt": {"correlationId": "11111111-1111-4111-8111-111111111111",
                   "pid": 42, "startTicks": 99, "diskDevice": 1, "diskInode": 2}}
        local = {"correlationId": "11111111-1111-4111-8111-111111111111"}
        result = census.classify(raw, local_claim=local)
        self.assertEqual(result["processes"][0]["claimedRole"], "windows-baseline")

        raw["processes"][0]["tcpListeners"] = [{"inode": 8, "port": 5927,
                                                  "bindAddress": "other"}]
        self.assertEqual(census.classify(raw, local_claim=local)["processes"][0]["claimedRole"],
                         "unknown")
        raw["processes"][0]["tcpListeners"] = []
        self.assertEqual(census.classify(raw, local_claim=local)["processes"][0]["claimedRole"],
                         "unknown")

    def test_remote_proc_census_marks_unreadable_live_fd_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            (proc / "42/fd").mkdir(parents=True)
            (proc / "net").mkdir()
            (proc / "1/ns").mkdir(parents=True)
            (proc / "self/ns").mkdir(parents=True)
            (proc / "1/comm").write_text("systemd\n")
            (proc / "1/ns/pid").symlink_to("pid:[4026531836]")
            (proc / "self/ns/pid").symlink_to("pid:[4026531836]")
            (proc / "self/mountinfo").write_text(
                f"1 0 0:1 / {proc} rw,nosuid,nodev,noexec,relatime - proc proc rw\n")
            (proc / "net/unix").write_text("Num RefCount Protocol Flags Type St Inode Path\n")
            for kind in ("tcp", "tcp6"):
                (proc / "net" / kind).write_text("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
            executable = root / "qemu-system-x86_64"
            executable.write_bytes(b"x")
            disk = root / "task.qcow2"
            disk.write_bytes(b"disk")
            (proc / "42/exe").symlink_to(executable)
            (proc / "42/fd/0").symlink_to(disk)
            (proc / "42/comm").write_text("qemu-system-x86\n")
            (proc / "42/stat").write_text("42 (qemu) " + " ".join(["0"] * 19 + ["99"]) + "\n")
            (proc / "42/cmdline").write_bytes(b"qemu-system-x86_64\0-m\0" + b"6144\0")
            script = (census._REMOTE.replace("pwd.getpwuid(os.geteuid()).pw_name!='kardinal'", "False")
                      .replace("__GUEST__", repr(str(root / "absent-guest")))
                      .replace("__WIN__", repr("a" * 64))
                      .replace("__DRV__", repr("b" * 64))
                      .replace("/proc", str(proc)))

            def run():
                result = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                        capture_output=True, text=True, check=True)
                return json.loads(result.stdout)

            good = run()
            self.assertTrue(good["censusComplete"], good)
            self.assertEqual(good["processes"][0]["startTicks"], 99)
            (proc / "self/mountinfo").write_text(
                f"1 0 0:1 / {proc} rw,hidepid=2 - proc proc rw,hidepid=2\n")
            hidden = run()
            self.assertFalse(hidden["censusComplete"])
            (proc / "self/mountinfo").write_text(
                f"1 0 0:1 / {proc} rw,nosuid,nodev,noexec,relatime - proc proc rw\n")
            (proc / "42/fd/0").unlink()
            (proc / "42/fd/0").symlink_to(root / "missing.qcow2")
            bad = run()
            self.assertFalse(bad["censusComplete"])
            self.assertEqual(bad["processes"][0]["state"], "unknown")

    def test_remote_tcp_parser_binds_listener_inode_column(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            (proc / "net").mkdir(parents=True)
            (proc / "net/unix").write_text("Num RefCount Protocol Flags Type St Inode Path\n")
            (proc / "net/tcp6").write_text("header\n")
            (proc / "net/tcp").write_text(
                "header\n0: 0100007F:170F 00000000:0000 0A 0:0 00:0 0 1000 0 12345\n")
            script = (census._REMOTE.replace("pwd.getpwuid(os.geteuid()).pw_name!='kardinal'", "False")
                      .replace("__GUEST__", repr(str(Path(directory) / "absent")))
                      .replace("__WIN__", repr("a" * 64))
                      .replace("__DRV__", repr("b" * 64))
                      .replace("/proc", str(proc))
                      .replace("unix,tcp=sockets();complete,items=scan(unix,tcp)",
                               "unix,tcp=sockets();print(json.dumps({'port':tcp.get(12345)}));complete,items=scan(unix,tcp)"))
            output = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                    capture_output=True, text=True, check=True).stdout.splitlines()
            self.assertEqual(json.loads(output[0])["port"], [5903, "127.0.0.1"])

    def test_remote_memory_accepts_single_digit_gib_qemu_argv(self):
        script = (census._REMOTE.replace("pwd.getpwuid(os.geteuid()).pw_name!='kardinal'", "False")
                  .replace("__GUEST__", repr("/absent-guest"))
                  .replace("__WIN__", repr("a" * 64))
                  .replace("__DRV__", repr("b" * 64))
                  .replace("unix,tcp=sockets();complete,items=scan(unix,tcp)",
                           "print(json.dumps({'memory':memory(['qemu-system-x86_64','-m','6G'])}));"
                           "unix,tcp=sockets();complete,items=scan(unix,tcp)"))
        output = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual(json.loads(output[0])["memory"], 6144)

    def test_remote_memory_diagnostic_never_echoes_arbitrary_argv(self):
        script = (census._REMOTE.replace("pwd.getpwuid(os.geteuid()).pw_name!='kardinal'", "False")
                  .replace("__GUEST__", repr("/absent-guest"))
                  .replace("__WIN__", repr("a" * 64))
                  .replace("__DRV__", repr("b" * 64))
                  .replace("unix,tcp=sockets();complete,items=scan(unix,tcp)",
                           "print(json.dumps({'safe':memory_diagnostic('size=4G,slots=4,maxmem=16G'),"
                           "'secret':memory_diagnostic('password=SecretValue')}));"
                           "unix,tcp=sockets();complete,items=scan(unix,tcp)"))
        output = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual(json.loads(output[0]),
                         {"safe": "size=4G,slots=4,maxmem=16G", "secret": None})


if __name__ == "__main__":
    unittest.main()

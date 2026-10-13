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


def _binary_capture_capable():
    if os.name != 'posix':
        return False
    try:
        import fcntl
    except ImportError:
        return False
    return callable(getattr(fcntl, 'flock', None))


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
            (proc / "1/stat").write_text("1 (systemd) " + " ".join(["0"] * 19 + ["1"]) + "\n")
            systemd = root / "systemd"
            systemd.write_bytes(b"systemd")
            (proc / "1/exe").symlink_to(systemd)
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

    def test_measured_headless_memory_declaration_reaches_observed_census(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            (proc / "42/fd").mkdir(parents=True)
            (proc / "net").mkdir()
            (proc / "1/ns").mkdir(parents=True)
            (proc / "self/ns").mkdir(parents=True)
            (proc / "1/comm").write_text("systemd\n")
            (proc / "1/stat").write_text("1 (systemd) " + " ".join(["0"] * 19 + ["1"]) + "\n")
            systemd = root / "systemd"
            systemd.write_bytes(b"systemd")
            (proc / "1/exe").symlink_to(systemd)
            for owner in ("1", "self"):
                (proc / owner / "ns/pid").symlink_to("pid:[4026531836]")
            (proc / "self/mountinfo").write_text(
                f"1 0 0:1 / {proc} rw,nosuid,nodev,noexec,relatime - proc proc rw\n")
            (proc / "net/unix").write_text("Num RefCount Protocol Flags Type St Inode Path\n")
            for kind in ("tcp", "tcp6"):
                (proc / "net" / kind).write_text("header\n")
            executable = root / "qemu-system-x86_64-headless"
            executable.write_bytes(b"x")
            (proc / "42/exe").symlink_to(executable)
            (proc / "42/comm").write_text("qemu-system-x86\n")
            (proc / "42/stat").write_text("42 (qemu) " + " ".join(["0"] * 19 + ["99"]) + "\n")
            (proc / "42/cmdline").write_bytes(b"qemu-system-x86_64-headless\0-memory\0" + b"2048\0")
            script = (census._REMOTE.replace("pwd.getpwuid(os.geteuid()).pw_name!='kardinal'", "False")
                      .replace("__GUEST__", repr(str(root / "absent-guest")))
                      .replace("__WIN__", repr("a" * 64))
                      .replace("__DRV__", repr("b" * 64))
                      .replace("/proc", str(proc)))
            output = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                    capture_output=True, text=True, check=True)
            raw = json.loads(output.stdout)
            self.assertTrue(raw["censusComplete"], raw)
            self.assertEqual(raw["processes"][0]["allocatedMemoryMiB"], 2048)
            result = census.classify(raw, local_claim=None)
            self.assertTrue(result["inventoryComplete"])
            self.assertEqual(result["processes"][0]["claimedRole"], "unknown")

    def test_measured_headless_executable_stays_unattributed(self):
        raw = {"schemaVersion": 1, "host": "archlinux", "censusComplete": True,
               "processes": [{"pid": 42, "startTicks": 99, "state": "observed",
                   "exe": "qemu-system-x86_64-headless", "allocatedMemoryMiB": 2048,
                   "disks": [], "qmpSockets": [], "tcpListeners": []}],
               "windowsBaselineReceipt": None}
        result = census.classify(raw, local_claim=None)
        self.assertEqual(result["processes"][0]["claimedRole"], "unknown")

    def test_headless_memory_rejects_ambiguous_or_opaque_declarations(self):
        import ast
        import re
        function = next(node for node in ast.parse(census._REMOTE).body
                        if isinstance(node, ast.FunctionDef) and node.name == "memory")
        namespace = {"re": re}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "actual-remote-memory", "exec"), namespace)
        memory = namespace["memory"]
        for argv in (["-memory", "2048", "-m", "2048"],
                     ["-memory", "2048", "-memory", "2048"],
                     ["-memory", "2048", "-m=4096"],
                     ["-memory", "2048", "-m4096"],
                     ["-memory", "2G"], ["-memory", "2048,slots=4"],
                     ["-memory", "127"], ["-memory", "65537"],
                     ["-memory", "02048"], ["-memory"],
                     ["-m", "4G,slots=4"]):
            with self.subTest(argv=argv):
                self.assertIsNone(memory(["qemu-system-x86_64-headless", *argv]))
        self.assertEqual(memory(["qemu-system-x86_64", "-m", "6G"]), 6144)

    def _exe_first_proc_fixture(self, rows, *, change_generation=False, change_executable=False, change_marker=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            (proc / "net").mkdir(parents=True)
            for owner in ("1", "self"):
                (proc / owner / "ns").mkdir(parents=True)
                (proc / owner / "ns/pid").symlink_to("pid:[4026531836]")
            (proc / "self/mountinfo").write_text(
                f"1 0 0:1 / {proc} rw,nosuid,nodev,noexec,relatime - proc proc rw\n")
            (proc / "net/unix").write_text("header\n")
            for kind in ("tcp", "tcp6"):
                (proc / "net" / kind).write_text("header\n")

            def stat_text(pid, ticks, state="S", flags=0):
                fields = [state] + ["0"] * 18 + [str(ticks)]
                fields[6] = str(flags)
                return f"{pid} (fixture) " + " ".join(fields) + "\n"

            all_rows = [{"pid": 1, "ticks": 1, "comm": "systemd", "exe": "systemd"}, *rows]
            for row in all_rows:
                child = proc / str(row["pid"])
                (child / "fd").mkdir(parents=True, exist_ok=True)
                (child / "comm").write_text(row["comm"] + "\n")
                (child / "stat").write_text(stat_text(row["pid"], row["ticks"],
                                                       row.get("state", "S"), row.get("flags", 0)))
                (child / "cmdline").write_bytes(b"qemu-system-x86_64\0-m\0" + b"4096\0")
                if row.get("unreadable_exe"):
                    (child / "exe").write_bytes(b"not a symlink")
                elif not row.get("missing_exe"):
                    executable = root / row["exe"]
                    executable.write_bytes(b"executable")
                    (child / "exe").symlink_to(executable)
            script = (census._REMOTE.replace("pwd.getpwuid(os.geteuid()).pw_name!='kardinal'", "False")
                      .replace("__GUEST__", repr(str(root / "absent-guest")))
                      .replace("__WIN__", repr("a" * 64))
                      .replace("__DRV__", repr("b" * 64))
                      .replace("/proc", str(proc)))
            if change_generation or change_executable:
                row = rows[0]
                cmdline = str(proc / str(row["pid"]) / "cmdline")
                mutation = ("Path(" + repr(str(proc / str(row["pid"]) / "stat")) + ").write_text(" +
                            repr(stat_text(row["pid"], row["ticks"] + 1)) + ")")
                if change_executable:
                    other = root / "qemu-system-aarch64"
                    other.write_bytes(b"other executable")
                    mutation = ("Path(" + repr(str(proc / str(row["pid"]) / "exe")) + ").unlink();" +
                                "Path(" + repr(str(proc / str(row["pid"]) / "exe")) + ").symlink_to(" + repr(str(other)) + ")")
                script = ("import builtins\nfrom pathlib import Path\nfixture_open=builtins.open\n"
                          "def mutate(path,*args,**kwargs):\n if str(path)==" + repr(cmdline) + ":\n  " + mutation + "\n return fixture_open(path,*args,**kwargs)\nbuiltins.open=mutate\n" + script)
            if change_marker:
                row = rows[-1]
                target = str(proc / str(row["pid"]) / "stat")
                changed = stat_text(row["pid"], row["ticks"] + (change_marker == "ticks"),
                                    "S" if change_marker == "state" else row.get("state", "S"),
                                    0 if change_marker == "flags" else row.get("flags", 0))
                prefix = ("import builtins\nfixture_open=builtins.open;stat_reads=0\n"
                          "class FixtureStat:\n def __init__(self,f):self.f=f\n def read(self,*args):\n  global stat_reads\n  data=self.f.read(*args);stat_reads+=1\n  if stat_reads==3:\n   with fixture_open(" + repr(target) + ", 'w') as out:out.write(" + repr(changed) + ")\n  return data\n def __del__(self):self.f.close()\n"
                          "def proof_boundary(path,*args,**kwargs):\n f=fixture_open(path,*args,**kwargs)\n return FixtureStat(f) if str(path)==" + repr(target) + " else f\nbuiltins.open=proof_boundary\n")
                script = prefix + script
            output = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                    capture_output=True, text=True, check=True)
            return json.loads(output.stdout)

    def test_actual_comm_7_generations_are_counted_by_executable(self):
        rows = [{"pid": 3726886, "ticks": 21863571, "comm": "7", "exe": "qemu-system-x86_64"},
                {"pid": 3847348, "ticks": 22216504, "comm": "7", "exe": "qemu-system-x86_64"}]
        raw = self._exe_first_proc_fixture(rows)
        self.assertTrue(raw["censusComplete"], raw)
        self.assertEqual([(x["pid"], x["startTicks"], x["allocatedMemoryMiB"]) for x in raw["processes"]],
                         [(3726886, 21863571, 4096), (3847348, 22216504, 4096)])
        self.assertTrue(all(x["claimedRole"] == "unknown" for x in census.classify(raw, local_claim=None)["processes"]))

    def test_renamed_live_unreadable_executable_keeps_census_unknown(self):
        raw = self._exe_first_proc_fixture([{"pid": 42, "ticks": 99, "comm": "7", "exe": "qemu-system-x86_64", "unreadable_exe": True}])
        self.assertFalse(raw["censusComplete"], raw)
        self.assertFalse(census.classify(raw, local_claim=None)["inventoryComplete"])

    def test_exe_first_generation_and_executable_changes_fail_closed(self):
        row = {"pid": 42, "ticks": 99, "comm": "7", "exe": "qemu-system-x86_64"}
        for option in ("change_generation", "change_executable"):
            with self.subTest(option=option):
                raw = self._exe_first_proc_fixture([row], **{option: True})
                self.assertFalse(raw["censusComplete"], raw)
                self.assertEqual(raw["processes"][0]["state"], "unknown")

    def test_exe_first_excludes_only_same_generation_unallocated_processes(self):
        qemu = {"pid": 42, "ticks": 99, "comm": "7", "exe": "qemu-system-x86_64"}
        for state, flags in (("Z", 0), ("S", 0x00200000)):
            with self.subTest(state=state, flags=flags):
                raw = self._exe_first_proc_fixture([qemu, {"pid": 43, "ticks": 100, "comm": "7", "exe": "", "state": state, "flags": flags, "missing_exe": True}])
                self.assertTrue(raw["censusComplete"], raw)
                self.assertEqual([x["pid"] for x in raw["processes"]], [42])
        raw = self._exe_first_proc_fixture([qemu, {"pid": 43, "ticks": 100, "comm": "7", "exe": "", "state": "S", "flags": 0, "missing_exe": True}])
        self.assertFalse(raw["censusComplete"], raw)

    def test_exe_first_rejects_stale_kernel_or_zombie_markers(self):
        for change, state, flags in (("flags", "S", 0x00200000), ("state", "Z", 0),
                                     ("ticks", "S", 0x00200000), ("ticks", "Z", 0)):
            with self.subTest(change=change, state=state):
                row = {"pid": 43, "ticks": 100, "comm": "7", "exe": "",
                       "state": state, "flags": flags, "missing_exe": True}
                self.assertFalse(self._exe_first_proc_fixture([row], change_marker=change)["censusComplete"])

    def test_comm_or_argv_cannot_claim_ordinary_executable(self):
        raw = self._exe_first_proc_fixture([{"pid": 42, "ticks": 99,
                                            "comm": "qemu-system-x86", "exe": "python3"}])
        self.assertTrue(raw["censusComplete"], raw)
        self.assertEqual(raw["processes"], [])

    def test_live_exe_and_later_stat_unreadable_keeps_census_unknown(self):
        real_run = subprocess.run
        prefix = ("import builtins\nreal_fixture_open=builtins.open;stat_calls=0\n"
                  "def later_stat_unreadable(path,*args,**kwargs):\n global stat_calls\n"
                  " if str(path).endswith('/42/stat'):\n  stat_calls+=1\n"
                  "  if stat_calls>1:raise PermissionError('inert later stat unreadable')\n"
                  " return real_fixture_open(path,*args,**kwargs)\nbuiltins.open=later_stat_unreadable\n")

        def boundary(argv, **kwargs):
            argv = list(argv)
            argv[-1] = prefix + argv[-1]
            return real_run(argv, **kwargs)

        with patch.object(subprocess, "run", side_effect=boundary):
            raw = self._exe_first_proc_fixture([{"pid": 42, "ticks": 99, "comm": "7",
                                                "exe": "qemu-system-x86_64", "unreadable_exe": True}])
        self.assertFalse(raw["censusComplete"], raw)
        self.assertFalse(census.classify(raw, local_claim=None)["inventoryComplete"])

    def test_privileged_program_matches_actual_reviewed_direct_source(self):
        import hashlib
        self.assertEqual(hashlib.sha256(census._privileged_program().encode()).hexdigest(),
                         '68a29151a50dd071801097991eff538f6379f5ad0ababfc7abfc829f6938f665')
        with patch.object(census, '_REMOTE', census._REMOTE + '# changed'):
            with self.assertRaisesRegex(ValueError, 'privileged_source_changed'):
                census._privileged_program()

    def test_privileged_fixed_request_refuses_unsafe_inputs_before_transport(self):
        from agent_tools import ssh_direct_nested_channel as direct
        with patch.object(direct, 'Guard') as guard:
            for request in ({'host': 'other', 'timeoutSeconds': 1},
                            {'host': 'archlinux', 'timeoutSeconds': True},
                            {'host': 'archlinux', 'timeoutSeconds': 31},
                            {'host': 'archlinux', 'timeoutSeconds': 1, 'command': 'x'},
                            {'host': 'archlinux', 'timeoutSeconds': 1, 'password': 'x'}):
                with self.subTest(request=request), self.assertRaises(ValueError):
                    census.observe_privileged('.', request)
        guard.assert_not_called()

    @unittest.skipUnless(_binary_capture_capable(), 'POSIX binary pipe collector with fcntl required')
    def test_existing_binary_capture_keeps_large_output_and_private_stdin(self):
        payload = b'inert-only-private-input\n'
        argv = [sys.executable, '-I', '-B', '-c',
                "import sys;data=sys.stdin.buffer.read();assert data.endswith(b'\\n');sys.stdout.buffer.write(b'x'*23026)"]
        capture = census._privileged_capture(argv, payload, 2)
        self.assertTrue(capture['complete'], capture)
        self.assertEqual((capture['stdout'], capture['stderr']), (b'x'*23026, b''))
        self.assertNotIn(payload.decode().strip(), str(argv))

    @unittest.skipUnless(_binary_capture_capable(), 'POSIX binary pipe collector with fcntl required')
    def test_existing_binary_capture_refuses_overflow_and_deadline(self):
        overflow = census._privileged_capture([sys.executable, '-I', '-B', '-c',
                     "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*65537)"], b'inert\n', 2)
        self.assertTrue(overflow['overflow']);self.assertFalse(overflow['complete'])
        timeout = census._privileged_capture([sys.executable, '-I', '-B', '-c',
                    "import sys,time;sys.stdin.buffer.read();time.sleep(2)"], b'inert\n', 0.05)
        self.assertTrue(timeout['timeout']);self.assertFalse(timeout['complete'])

    def _privileged_projection_fixture(self):
        # Pure finite DTO projection: native emitted-script and whole-host proofs
        # are covered separately; these controls require no POSIX symlinks.
        sample = {'observedAtUnixMs': 1, 'availableMemoryBytes': 20*1024**3,
                  'psi': 'normal', 'psiSomeAvg10': 0.0, 'psiFullAvg10': 0.0,
                  'vmstat': {'pswpin': 0, 'pswpout': 0, 'oomKill': 0}}
        host = {'state': 'observed', 'physicalMemoryBytes': 32*1024**3,
                'swapUsedBytes': 0, 'samples': [sample, {**sample, 'observedAtUnixMs': 2}],
                'inventoryComplete': True, 'vms': [{'pid': 42, 'startTicks': 99,
                'qemuExecutable': 'qemu-system-x86_64', 'configuredMemoryBytes': 4*1024**3}]}
        holder = {'schemaVersion': 1, 'host': 'archlinux', 'censusComplete': True,
                  'windowsBaselineReceipt': None,
                  'processes': [{'pid': 42, 'startTicks': 99, 'state': 'observed',
                                 'exe': 'qemu-system-x86_64', 'allocatedMemoryMiB': host['vms'][0]['configuredMemoryBytes']//1048576,
                                 'disks': [], 'qmpSockets': [], 'tcpListeners': []}]}
        return {'scope': 'FIXED_PRIVILEGED_HOST_RESOURCE_AND_HOLDER_READ_ONLY',
                'effectiveUid': 0, 'hostBootId': '25515f23-b966-4c3a-ae63-d38452375578',
                'bootStable': True, 'hostInventoryStable': True, 'holderInventoryStable': True,
                'diskOwnerUid': 1000, 'diskAvailableBytes': 100000000000,
                'host': host, 'holder': holder}

    def test_privileged_projection_requires_complete_matching_populations(self):
        raw = self._privileged_projection_fixture()
        result = census._privileged_projection(raw, 1, 5)
        self.assertEqual(result['measurementAvailability'], 'complete')
        self.assertFalse(result['ready']);self.assertFalse(result['nativeActionAllowed'])
        self.assertEqual(result['holderCensus']['processes'][0]['claimedRole'], 'unknown')
        raw['holder']['processes'][0]['startTicks'] += 1
        with self.assertRaisesRegex(ValueError, 'privileged_inventory_unknown'):
            census._privileged_projection(raw, 1, 5)

    def test_privileged_projection_rejects_identity_or_partial_observation(self):
        original = self._privileged_projection_fixture()
        for key, value in (('effectiveUid', 1000), ('effectiveUid', False), ('hostBootId', 'different'),
                           ('bootStable', False), ('hostInventoryStable', False),
                           ('holderInventoryStable', False), ('diskOwnerUid', 0),
                           ('diskAvailableBytes', True)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                census._privileged_projection({**original, key: value}, 1, 5)
        original['host']['inventoryComplete'] = False
        with self.assertRaisesRegex(ValueError, 'privileged_inventory_unknown'):
            census._privileged_projection(original, 1, 5)

    def test_privileged_pure_controls_and_collector_skip_without_fcntl(self):
        source = str(Path(census.__file__).resolve().parents[1])
        script = """import importlib.abc,importlib.util,json,sys,unittest
sys.path.insert(0,sys.argv[2])
# Admit unchanged baseline imports, then make the newly needed runtime module absent.
from agent_tools import arch_qemu_holder_census
class AbsentFcntl(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='fcntl':raise ModuleNotFoundError("No module named 'fcntl'",name='fcntl')
sys.modules.pop('fcntl',None);sys.meta_path.insert(0,AbsentFcntl())
spec=importlib.util.spec_from_file_location('fresh_owned_probe',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
names=['test_privileged_fixed_request_refuses_unsafe_inputs_before_transport','test_privileged_projection_requires_complete_matching_populations','test_privileged_projection_rejects_identity_or_partial_observation','test_existing_binary_capture_keeps_large_output_and_private_stdin','test_existing_binary_capture_refuses_overflow_and_deadline']
suite=unittest.TestSuite(module.ArchQemuHolderCensusTest(name) for name in names)
result=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'tests':result.testsRun,'skips':len(result.skipped),'errors':len(result.errors),'failures':len(result.failures)}))
raise SystemExit(not result.wasSuccessful())
"""
        result = subprocess.run([sys.executable, '-B', '-c', script, str(Path(__file__).resolve()), source],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'tests': 5, 'skips': 2, 'errors': 0, 'failures': 0})

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
